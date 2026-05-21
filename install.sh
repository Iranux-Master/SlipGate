#!/bin/bash

: <<'IRANUX_METADATA'
{
  "standard": {
    "name": "iranux-script-metadata",
    "schema_version": "1.0"
  },
  "script": {
    "id": "slipgate-flag-based-installer",
    "name": "SlipGate Flag-Based Installer",
    "version": "1.0.0",
    "description": "Downloads the SlipGate binary and runs a non-interactive installation using command-line flags."
  },
  "risk": {
    "level": "high"
  },
  "requirements": {
    "requires_root": true,
    "requires_internet": true,
    "supported_os": ["linux"],
    "required_commands": ["uname", "tr", "chmod", "mkdir", "rm", "killall"]
  }
}
IRANUX_METADATA

# SlipGate Iranux-compatible installer.
# This script expects a SlipGate binary that supports:
#   slipgate install --non-interactive --flags...
# It intentionally collects all install inputs before running the binary.

set -e

REPO="anonvector/slipgate"

: <<'IRANUX_PARAM'
{
  "name": "install_dir",
  "label": "Install Directory",
  "description": "Directory where the SlipGate binary will be installed.",
  "type": "path",
  "required": true,
  "default": "/usr/local/bin",
  "example": "/usr/local/bin",
  "group": "Download Settings"
}
IRANUX_PARAM

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

: <<'IRANUX_PARAM'
{
  "name": "slipgate_release_tag",
  "label": "SlipGate Release Tag",
  "description": "Optional SlipGate release tag, for example v1.5.1. Leave empty to download the latest stable release.",
  "type": "string",
  "required": false,
  "placeholder": "v1.5.1",
  "group": "Download Settings"
}
IRANUX_PARAM

SLIPGATE_RELEASE_TAG="${SLIPGATE_RELEASE_TAG:-}"

: <<'IRANUX_PARAM'
{
  "name": "transports",
  "label": "Transports",
  "description": "Select SlipGate transports to install. The Iranux runner should pass selected values as a comma-separated string.",
  "type": "multi_select",
  "required": true,
  "options": [
    { "label": "DNSTT / NoizDNS", "value": "dnstt" },
    { "label": "VayDNS", "value": "vaydns" },
    { "label": "Slipstream", "value": "slipstream" },
    { "label": "NaiveProxy", "value": "naive" },
    { "label": "SSH", "value": "ssh" },
    { "label": "SOCKS5", "value": "socks" },
    { "label": "StunTLS", "value": "stuntls" }
  ],
  "group": "Tunnel Settings"
}
IRANUX_PARAM

TRANSPORTS="${TRANSPORTS:-}"

: <<'IRANUX_PARAM'
{
  "name": "backend",
  "label": "Backend",
  "description": "Backend used by domain-based transports. Direct SSH/SOCKS/StunTLS transports ignore this value.",
  "type": "enum",
  "required": false,
  "default": "socks",
  "options": [
    { "label": "SOCKS", "value": "socks" },
    { "label": "SSH", "value": "ssh" },
    { "label": "Both", "value": "both" }
  ],
  "group": "Tunnel Settings"
}
IRANUX_PARAM

BACKEND="${BACKEND:-socks}"

: <<'IRANUX_PARAM'
{
  "name": "base_domain",
  "label": "Base Domain",
  "description": "Base domain used to derive transport domains. Example: dnstt = t.example.com, vaydns = v.example.com, slipstream = s.example.com, naive = example.com.",
  "type": "domain",
  "required": false,
  "example": "example.com",
  "group": "Domain Settings"
}
IRANUX_PARAM

BASE_DOMAIN="${BASE_DOMAIN:-}"

: <<'IRANUX_PARAM'
{
  "name": "dnstt_domain",
  "label": "DNSTT Domain",
  "description": "Optional explicit domain for DNSTT/NoizDNS. If empty, SlipGate derives it from Base Domain.",
  "type": "domain",
  "required": false,
  "example": "t.example.com",
  "group": "Domain Settings"
}
IRANUX_PARAM

DNSTT_DOMAIN="${DNSTT_DOMAIN:-}"

: <<'IRANUX_PARAM'
{
  "name": "vaydns_domain",
  "label": "VayDNS Domain",
  "description": "Optional explicit domain for VayDNS. If empty, SlipGate derives it from Base Domain.",
  "type": "domain",
  "required": false,
  "example": "v.example.com",
  "group": "Domain Settings"
}
IRANUX_PARAM

VAYDNS_DOMAIN="${VAYDNS_DOMAIN:-}"

: <<'IRANUX_PARAM'
{
  "name": "slipstream_domain",
  "label": "Slipstream Domain",
  "description": "Optional explicit domain for Slipstream. If empty, SlipGate derives it from Base Domain.",
  "type": "domain",
  "required": false,
  "example": "s.example.com",
  "group": "Domain Settings"
}
IRANUX_PARAM

SLIPSTREAM_DOMAIN="${SLIPSTREAM_DOMAIN:-}"

: <<'IRANUX_PARAM'
{
  "name": "naive_domain",
  "label": "NaiveProxy Domain",
  "description": "Optional explicit domain for NaiveProxy. If empty, SlipGate uses Base Domain.",
  "type": "domain",
  "required": false,
  "example": "example.com",
  "group": "Domain Settings"
}
IRANUX_PARAM

NAIVE_DOMAIN="${NAIVE_DOMAIN:-}"

: <<'IRANUX_PARAM'
{
  "name": "mtu",
  "label": "MTU",
  "description": "MTU used for DNS-based transports such as DNSTT and VayDNS.",
  "type": "int",
  "required": false,
  "default": 1280,
  "example": 1280,
  "group": "Tunnel Settings"
}
IRANUX_PARAM

MTU="${MTU:-1280}"

: <<'IRANUX_PARAM'
{
  "name": "vaydns_record_type",
  "label": "VayDNS Record Type",
  "description": "DNS record type used by VayDNS. Use a value supported by the SlipGate binary.",
  "type": "string",
  "required": false,
  "placeholder": "TXT",
  "group": "Tunnel Settings"
}
IRANUX_PARAM

VAYDNS_RECORD_TYPE="${VAYDNS_RECORD_TYPE:-}"

: <<'IRANUX_PARAM'
{
  "name": "stuntls_port",
  "label": "StunTLS Port",
  "description": "TLS listen port used by StunTLS.",
  "type": "port",
  "required": false,
  "default": 443,
  "example": 443,
  "group": "Tunnel Settings"
}
IRANUX_PARAM

STUNTLS_PORT="${STUNTLS_PORT:-443}"

: <<'IRANUX_PARAM'
{
  "name": "naive_email",
  "label": "NaiveProxy Email",
  "description": "Email used for NaiveProxy certificate setup.",
  "type": "email",
  "required": false,
  "example": "admin@example.com",
  "group": "NaiveProxy Settings"
}
IRANUX_PARAM

NAIVE_EMAIL="${NAIVE_EMAIL:-}"

: <<'IRANUX_PARAM'
{
  "name": "naive_decoy_url",
  "label": "NaiveProxy Decoy URL",
  "description": "Decoy URL used by NaiveProxy.",
  "type": "url",
  "required": false,
  "example": "https://www.microsoft.com",
  "group": "NaiveProxy Settings"
}
IRANUX_PARAM

NAIVE_DECOY_URL="${NAIVE_DECOY_URL:-}"

: <<'IRANUX_PARAM'
{
  "name": "create_user",
  "label": "Create User",
  "description": "Choose whether SlipGate should create an OS user during installation.",
  "type": "enum",
  "required": true,
  "default": "Y",
  "options": [
    { "label": "Yes", "value": "Y" },
    { "label": "No", "value": "N" }
  ],
  "group": "User Settings"
}
IRANUX_PARAM

CREATE_USER="${CREATE_USER:-Y}"

: <<'IRANUX_PARAM'
{
  "name": "username",
  "label": "Username",
  "description": "Username to create if user creation is enabled.",
  "type": "string",
  "required": false,
  "default": "user1",
  "group": "User Settings"
}
IRANUX_PARAM

USERNAME="${USERNAME:-user1}"

: <<'IRANUX_PARAM'
{
  "name": "password",
  "label": "Password",
  "description": "Password for the created user. Leave empty to let SlipGate generate one.",
  "type": "password",
  "required": false,
  "group": "User Settings"
}
IRANUX_PARAM

PASSWORD="${PASSWORD:-}"

: <<'IRANUX_PARAM'
{
  "name": "enable_warp",
  "label": "Enable WARP",
  "description": "Choose whether to enable Cloudflare WARP outbound routing.",
  "type": "enum",
  "required": true,
  "default": "N",
  "options": [
    { "label": "Yes", "value": "Y" },
    { "label": "No", "value": "N" }
  ],
  "group": "WARP Settings"
}
IRANUX_PARAM

ENABLE_WARP="${ENABLE_WARP:-N}"

: <<'IRANUX_PARAM'
{
  "name": "warp_ipv6",
  "label": "Route IPv6 Through WARP",
  "description": "Choose whether IPv6 traffic should be routed through WARP.",
  "type": "enum",
  "required": false,
  "default": "N",
  "options": [
    { "label": "Yes", "value": "Y" },
    { "label": "No", "value": "N" }
  ],
  "group": "WARP Settings"
}
IRANUX_PARAM

WARP_IPV6="${WARP_IPV6:-N}"

: <<'IRANUX_PARAM'
{
  "name": "offline_bin_dir",
  "label": "Offline Binary Directory",
  "description": "Optional local directory used by SlipGate for offline dependency binaries.",
  "type": "path",
  "required": false,
  "placeholder": "/path/to/binaries",
  "group": "Advanced Settings"
}
IRANUX_PARAM

OFFLINE_BIN_DIR="${OFFLINE_BIN_DIR:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[1;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && error "This script must be run as root (sudo)"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *)       error "Unsupported architecture: $ARCH" ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
[[ "$OS" != "linux" ]] && error "SlipGate only supports Linux"

BINARY="slipgate-${OS}-${ARCH}"

if [[ -n "$SLIPGATE_RELEASE_TAG" ]]; then
    URL="https://github.com/${REPO}/releases/download/${SLIPGATE_RELEASE_TAG}/${BINARY}"
else
    URL="https://github.com/${REPO}/releases/latest/download/${BINARY}"
fi

echo -e "${CYAN}"
echo "   _____ _ _       _____       _       "
echo "  / ____| (_)     / ____|     | |      "
echo " | (___ | |_ _ __| |  __  __ _| |_ ___ "
echo "  \___ \| | | '_ \ | |_ |/ _\` | __/ _ \\"
echo "  ____) | | | |_) | |__| | (_| | ||  __/"
echo " |_____/|_|_| .__/ \_____|\__,_|\__\___|"
echo "             | |                         "
echo "             |_|                         "
echo -e "${NC}"

mkdir -p "$INSTALL_DIR"

killall slipgate 2>/dev/null || true
killall dnstt-server 2>/dev/null || true
killall slipstream-server 2>/dev/null || true
rm -f "${INSTALL_DIR}/slipgate"

info "Downloading slipgate ($OS/$ARCH)..."
if command -v curl &>/dev/null; then
    curl -fsSL "$URL" -o "${INSTALL_DIR}/slipgate"
elif command -v wget &>/dev/null; then
    wget -qO "${INSTALL_DIR}/slipgate" "$URL"
else
    error "Neither curl nor wget found"
fi

chmod +x "${INSTALL_DIR}/slipgate"

INSTALL_ARGS=(
  install
  --non-interactive
  --transports "$TRANSPORTS"
  --backend "$BACKEND"
  --mtu "$MTU"
  --stuntls-port "$STUNTLS_PORT"
  --create-user "$CREATE_USER"
  --username "$USERNAME"
  --enable-warp "$ENABLE_WARP"
  --warp-ipv6 "$WARP_IPV6"
)

[[ -n "$BASE_DOMAIN" ]] && INSTALL_ARGS+=(--base-domain "$BASE_DOMAIN")
[[ -n "$DNSTT_DOMAIN" ]] && INSTALL_ARGS+=(--dnstt-domain "$DNSTT_DOMAIN")
[[ -n "$VAYDNS_DOMAIN" ]] && INSTALL_ARGS+=(--vaydns-domain "$VAYDNS_DOMAIN")
[[ -n "$SLIPSTREAM_DOMAIN" ]] && INSTALL_ARGS+=(--slipstream-domain "$SLIPSTREAM_DOMAIN")
[[ -n "$NAIVE_DOMAIN" ]] && INSTALL_ARGS+=(--naive-domain "$NAIVE_DOMAIN")
[[ -n "$VAYDNS_RECORD_TYPE" ]] && INSTALL_ARGS+=(--vaydns-record-type "$VAYDNS_RECORD_TYPE")
[[ -n "$NAIVE_EMAIL" ]] && INSTALL_ARGS+=(--naive-email "$NAIVE_EMAIL")
[[ -n "$NAIVE_DECOY_URL" ]] && INSTALL_ARGS+=(--naive-decoy-url "$NAIVE_DECOY_URL")
[[ -n "$PASSWORD" ]] && INSTALL_ARGS+=(--password "$PASSWORD")
[[ -n "$OFFLINE_BIN_DIR" ]] && INSTALL_ARGS+=(--bin-dir "$OFFLINE_BIN_DIR")

info "Running SlipGate non-interactive install..."
"${INSTALL_DIR}/slipgate" "${INSTALL_ARGS[@]}"

info "Done! Run 'sudo slipgate' to see the menu."
echo "__IRANUX_REACHED_END_V1__"
exit 0
