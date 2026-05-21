// slipgate_install_flag_mode_patch.go
//
// SlipGate non-interactive flag-based install support for Iranux.
//
// Place this file in the same package as the existing system install handler:
//
//     package handlers
//
// This file adds the non-interactive install-plan builder used by:
//
//     slipgate install --non-interactive --flags...
//
// IMPORTANT:
// This file is designed to be integrated with the existing install handler.
// It does not replace the full handler by itself. The existing handler should
// be refactored into:
//
//     collectSystemInstallPlanInteractive(ctx, out, cfg)
//     collectSystemInstallPlanFromFlags(ctx, out, cfg)
//     runSystemInstallPlan(ctx, out, cfg, plan)
//
// The uploaded installer already has a clear split between:
//     PHASE 1 — interactive prompt collection
//     PHASE 2 — non-interactive installation
//
// Interactive mode should keep the current prompt behavior.
// Non-interactive mode should call collectSystemInstallPlanFromFlags and then
// run the same Phase 2 install logic.
//
// Required install flags to register:
//
//     --non-interactive
//     --transports
//     --backend
//     --base-domain
//     --dnstt-domain
//     --vaydns-domain
//     --slipstream-domain
//     --naive-domain
//     --dnstt-ssh-domain
//     --vaydns-ssh-domain
//     --slipstream-ssh-domain
//     --mtu
//     --vaydns-record-type
//     --stuntls-port
//     --naive-email
//     --naive-decoy-url
//     --create-user
//     --username
//     --password
//     --enable-warp
//     --warp-ipv6
//     --bin-dir
//
// Transport selection supports both:
//     --transports "all"
//     --transports "8"
// as aliases for all supported transports.
//
// Recommended stable value for Iranux UI:
//     all
//
// Backward-compatible accepted value:
//     8

package handlers

import (
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/system"
)

// installOutput is intentionally small so this patch does not depend on the
// concrete output type used by actions.Context.
type installOutput interface {
	Info(string)
	Warning(string)
}

// systemInstallPlan is the shared structure between interactive prompt mode
// and non-interactive flag mode.
type systemInstallPlan struct {
	Transports     []string
	PlannedTunnels []config.TunnelConfig

	DirectSOCKS bool
	SetupSOCKS  bool

	CreateUser  bool
	NewUsername string
	NewPassword string

	EnableWarp bool
	WarpIPv6   bool
}

// collectSystemInstallPlanFromFlags builds the same install plan normally
// produced by the interactive prompt phase, but reads values from flags.
//
// This function must never call prompt.*.
func collectSystemInstallPlanFromFlags(
	ctx *actions.Context,
	out installOutput,
	cfg *config.Config,
) (*systemInstallPlan, error) {
	rawTransports := splitCSV(ctx.GetArg("transports"))
	transports := expandTransportSelection(rawTransports)

	if len(transports) == 0 {
		return nil, actions.NewError(actions.SystemInstall, "--transports is required in non-interactive mode", nil)
	}

	backend := strings.TrimSpace(ctx.GetArg("backend"))
	if backend == "" {
		backend = config.BackendSOCKS
	}

	baseDomain := strings.TrimSpace(ctx.GetArg("base-domain"))
	mtu := intArg(ctx, "mtu", config.DefaultMTU)
	stunTLSPort := intArg(ctx, "stuntls-port", 443)
	vayDNSRecordType := strings.TrimSpace(ctx.GetArg("vaydns-record-type"))
	naiveEmail := strings.TrimSpace(ctx.GetArg("naive-email"))
	naiveDecoyURL := strings.TrimSpace(ctx.GetArg("naive-decoy-url"))

	createUser := yesNo(ctx.GetArg("create-user"), false)
	newUsername := strings.TrimSpace(ctx.GetArg("username"))
	newPassword := ctx.GetArg("password")

	if createUser {
		if newUsername == "" {
			newUsername = "user1"
		}
		if newPassword == "" {
			newPassword = system.GeneratePassword(16)
			out.Info(fmt.Sprintf("Generated password: %s", newPassword))
		} else if err := config.ValidatePassword(newPassword); err != nil {
			return nil, actions.NewError(actions.SystemInstall, err.Error(), nil)
		}
	}

	enableWarp := yesNo(ctx.GetArg("enable-warp"), false)
	warpIPv6 := yesNo(ctx.GetArg("warp-ipv6"), false)

	needsBackend := false
	for _, t := range transports {
		if t != config.TransportSSH && t != config.TransportSOCKS && t != config.TransportStunTLS {
			needsBackend = true
			break
		}
	}

	if !needsBackend {
		backend = ""
	}

	var backends []string
	if needsBackend {
		switch backend {
		case config.BackendSOCKS, config.BackendSSH:
			backends = []string{backend}
		case "both":
			backends = []string{config.BackendSOCKS, config.BackendSSH}
		default:
			return nil, actions.NewError(actions.SystemInstall, "invalid --backend value", nil)
		}
	}

	var plannedTunnels []config.TunnelConfig
	directSOCKS := false
	setupSOCKS := false

	for _, selectedTransport := range transports {
		switch selectedTransport {
		case config.TransportSSH, config.TransportSOCKS, config.TransportStunTLS:
			implicitBackend := config.BackendSSH

			if selectedTransport == config.TransportSOCKS {
				implicitBackend = config.BackendSOCKS
				directSOCKS = true
			}

			tag := cfg.UniqueTag(selectedTransport)
			tunnel := config.TunnelConfig{
				Tag:       tag,
				Transport: selectedTransport,
				Backend:   implicitBackend,
				Enabled:   true,
			}

			if selectedTransport == config.TransportStunTLS {
				tunnelDir := config.TunnelDir(tag)
				tunnel.StunTLS = &config.StunTLSConfig{
					Cert: filepath.Join(tunnelDir, "cert.pem"),
					Key:  filepath.Join(tunnelDir, "key.pem"),
					Port: stunTLSPort,
				}
			}

			if err := cfg.ValidateNewTunnel(&tunnel); err != nil {
				out.Warning(fmt.Sprintf("Skip %s: %v", tag, err))
				continue
			}

			cfg.AddTunnel(tunnel)
			plannedTunnels = append(plannedTunnels, tunnel)

			if selectedTransport == config.TransportSOCKS {
				setupSOCKS = true
			}

			continue

		case config.TransportDNSTT, config.TransportVayDNS, config.TransportSlipstream, config.TransportNaive:
			// handled below
		default:
			return nil, actions.NewError(actions.SystemInstall, fmt.Sprintf("unsupported transport: %s", selectedTransport), nil)
		}

		domain := domainForTransport(ctx, selectedTransport, baseDomain)
		if domain == "" {
			return nil, actions.NewError(actions.SystemInstall, fmt.Sprintf("domain is required for transport %s", selectedTransport), nil)
		}

		if selectedTransport == config.TransportNaive {
			if naiveEmail == "" {
				naiveEmail = "admin@" + baseDomainOf(domain)
			}
			if naiveDecoyURL == "" {
				// Deterministic fallback for non-interactive installs.
				naiveDecoyURL = "https://www.microsoft.com"
			}
		}

		for bIdx, b := range backends {
			// NaiveProxy is a single service; it serves both client-visible variants.
			if selectedTransport == config.TransportNaive && bIdx > 0 {
				break
			}

			tag := cfg.UniqueTag(selectedTransport)
			tunnelDomain := domain

			if backend == "both" && selectedTransport != config.TransportNaive {
				tag = cfg.UniqueTag(selectedTransport + "-" + b)

				if b == config.BackendSSH {
					tunnelDomain = sshDomainForTransport(ctx, selectedTransport, baseDomain, domain)
				}
			}

			tunnelDir := config.TunnelDir(tag)
			tunnel := config.TunnelConfig{
				Tag:       tag,
				Transport: selectedTransport,
				Backend:   b,
				Domain:    tunnelDomain,
				Enabled:   true,
			}

			if tunnel.IsDNSTunnel() {
				tunnel.Port = cfg.NextAvailablePort()
				for _, ex := range plannedTunnels {
					if ex.Port == tunnel.Port {
						tunnel.Port++
					}
				}
			}

			switch selectedTransport {
			case config.TransportDNSTT:
				tunnel.DNSTT = &config.DNSTTConfig{
					MTU:        mtu,
					PrivateKey: filepath.Join(tunnelDir, "server.key"),
					PublicKey:  "",
				}

			case config.TransportVayDNS:
				tunnel.VayDNS = &config.VayDNSConfig{
					MTU:        mtu,
					PrivateKey: filepath.Join(tunnelDir, "server.key"),
					PublicKey:  "",
					RecordType: vayDNSRecordType,
				}

			case config.TransportSlipstream:
				tunnel.Slipstream = &config.SlipstreamConfig{
					Cert: filepath.Join(tunnelDir, "cert.pem"),
					Key:  filepath.Join(tunnelDir, "key.pem"),
				}

			case config.TransportNaive:
				tunnel.Naive = &config.NaiveConfig{
					Email:    naiveEmail,
					DecoyURL: naiveDecoyURL,
					Port:     443,
				}
				if createUser {
					tunnel.Naive.User = newUsername
					tunnel.Naive.Password = newPassword
				}
			}

			if err := cfg.ValidateNewTunnel(&tunnel); err != nil {
				out.Warning(fmt.Sprintf("Skip %s: %v", tag, err))
				continue
			}

			cfg.AddTunnel(tunnel)
			plannedTunnels = append(plannedTunnels, tunnel)

			if b == config.BackendSOCKS && selectedTransport != config.TransportNaive {
				setupSOCKS = true
			}
		}
	}

	if len(plannedTunnels) == 0 {
		return nil, actions.NewError(actions.SystemInstall, "no tunnels created from non-interactive flags", nil)
	}

	return &systemInstallPlan{
		Transports:      transports,
		PlannedTunnels:  plannedTunnels,
		DirectSOCKS:     directSOCKS,
		SetupSOCKS:      setupSOCKS,
		CreateUser:      createUser,
		NewUsername:     newUsername,
		NewPassword:     newPassword,
		EnableWarp:      enableWarp,
		WarpIPv6:        warpIPv6,
	}, nil
}

func splitCSV(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

// expandTransportSelection expands "all" or legacy menu value "8" into all
// supported transports and removes duplicates while preserving order.
//
// Iranux UI should send "all".
// "8" is accepted only for backward compatibility with old menu semantics.
func expandTransportSelection(values []string) []string {
	allTransports := []string{
		config.TransportDNSTT,
		config.TransportVayDNS,
		config.TransportSlipstream,
		config.TransportNaive,
		config.TransportSSH,
		config.TransportSOCKS,
		config.TransportStunTLS,
	}

	var expanded []string
	seen := map[string]bool{}

	add := func(v string) {
		v = normalizeTransportValue(v)
		if v == "" {
			return
		}
		if !seen[v] {
			seen[v] = true
			expanded = append(expanded, v)
		}
	}

	for _, v := range values {
		normalized := normalizeTransportValue(v)
		if normalized == "all" || normalized == "8" {
			for _, t := range allTransports {
				add(t)
			}
			continue
		}

		add(normalized)
	}

	return expanded
}

func normalizeTransportValue(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))

	switch v {
	case "all", "8":
		return v

	case "dnstt", "noizdns", "dnstt/noizdns":
		return config.TransportDNSTT

	case "vaydns", "vay-dns":
		return config.TransportVayDNS

	case "slipstream", "slipstream-server":
		return config.TransportSlipstream

	case "naive", "naiveproxy", "naive-proxy":
		return config.TransportNaive

	case "ssh":
		return config.TransportSSH

	case "socks", "socks5":
		return config.TransportSOCKS

	case "stuntls", "stun-tls", "stun_tls":
		return config.TransportStunTLS

	default:
		return v
	}
}

func flagBool(ctx *actions.Context, name string) bool {
	v := strings.ToLower(strings.TrimSpace(ctx.GetArg(name)))
	return v == "1" || v == "true" || v == "yes" || v == "y"
}

func yesNo(value string, defaultValue bool) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	switch v {
	case "y", "yes", "true", "1":
		return true
	case "n", "no", "false", "0":
		return false
	default:
		return defaultValue
	}
}

func intArg(ctx *actions.Context, name string, fallback int) int {
	raw := strings.TrimSpace(ctx.GetArg(name))
	if raw == "" {
		return fallback
	}

	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}

	return v
}

func domainForTransport(ctx *actions.Context, transportName, baseDomain string) string {
	switch transportName {
	case config.TransportDNSTT:
		if v := strings.TrimSpace(ctx.GetArg("dnstt-domain")); v != "" {
			return v
		}
		if baseDomain != "" {
			return "t." + baseDomain
		}

	case config.TransportVayDNS:
		if v := strings.TrimSpace(ctx.GetArg("vaydns-domain")); v != "" {
			return v
		}
		if baseDomain != "" {
			return "v." + baseDomain
		}

	case config.TransportSlipstream:
		if v := strings.TrimSpace(ctx.GetArg("slipstream-domain")); v != "" {
			return v
		}
		if baseDomain != "" {
			return "s." + baseDomain
		}

	case config.TransportNaive:
		if v := strings.TrimSpace(ctx.GetArg("naive-domain")); v != "" {
			return v
		}
		if baseDomain != "" {
			return baseDomain
		}
	}

	return ""
}

func sshDomainForTransport(ctx *actions.Context, transportName, baseDomain, fallback string) string {
	switch transportName {
	case config.TransportDNSTT:
		if v := strings.TrimSpace(ctx.GetArg("dnstt-ssh-domain")); v != "" {
			return v
		}
		if baseDomain != "" {
			return "ts." + baseDomain
		}

	case config.TransportVayDNS:
		if v := strings.TrimSpace(ctx.GetArg("vaydns-ssh-domain")); v != "" {
			return v
		}
		if baseDomain != "" {
			return "vs." + baseDomain
		}

	case config.TransportSlipstream:
		if v := strings.TrimSpace(ctx.GetArg("slipstream-ssh-domain")); v != "" {
			return v
		}
		if baseDomain != "" {
			return "ss." + baseDomain
		}
	}

	return fallback
}

func baseDomainOf(domain string) string {
	host, _, err := net.SplitHostPort(domain)
	if err == nil {
		domain = host
	}

	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}

	return strings.Join(parts[len(parts)-2:], ".")
}
