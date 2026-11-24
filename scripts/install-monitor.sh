#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SYSTEMD_DIR="/etc/systemd/system"
ENV_FILE="${ENV_FILE:-/etc/cert_monitor.env}"

usage() {
    cat <<'EOF'
Usage: sudo ./scripts/install-monitor.sh <user>

Install the optional cert-monitor MQTT expiry daemon for Home Assistant:
  1. Sync runtime dependencies via uv (--frozen --no-dev) as <user>.
  2. Install systemd/cert-monitor@.service into /etc/systemd/system.
  3. Enable and start cert-monitor@<user>.service.

Prerequisites:
  - /etc/cert_monitor.env exists (copy from config/cert_monitor.env.example).
  - uv is installed (in PATH or ~/.local/bin/uv).
EOF
}

if [[ "${1:-}" == '-h' || "${1:-}" == '--help' ]]; then
    usage
    exit 0
fi

if [[ $# -ne 1 ]]; then
    usage >&2
    exit 2
fi

TARGET_USER="$1"

if [[ ${EUID} -ne 0 ]]; then
    echo "Error: please run with sudo." >&2
    exit 1
fi

if ! id "${TARGET_USER}" >/dev/null 2>&1; then
    echo "Error: user '${TARGET_USER}' does not exist." >&2
    exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
    echo "Error: ${ENV_FILE} not found." >&2
    echo "Hint: sudo cp ${REPO_ROOT}/config/cert_monitor.env.example ${ENV_FILE}" >&2
    exit 1
fi

find_uv() {
    local home_dir candidate
    home_dir="$(getent passwd "${TARGET_USER}" | cut -d: -f6)"
    for candidate in \
        "${UV_BIN:-}" \
        "$(command -v uv 2>/dev/null || true)" \
        "${home_dir}/.local/bin/uv" \
        "${home_dir}/.cargo/bin/uv" \
        "/usr/local/bin/uv"; do
        if [[ -n "${candidate}" && -x "${candidate}" ]]; then
            printf '%s' "${candidate}"
            return 0
        fi
    done
    return 1
}

UV_PATH="$(find_uv || true)"
if [[ -z "${UV_PATH}" ]]; then
    echo "Error: uv binary not found for user '${TARGET_USER}'." >&2
    echo "Hint: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
    exit 1
fi

echo "Syncing Python environment with ${UV_PATH} as ${TARGET_USER}..."
sudo -u "${TARGET_USER}" "${UV_PATH}" sync --project "${REPO_ROOT}" --frozen --no-dev

install -m 0644 "${REPO_ROOT}/systemd/cert-monitor@.service" "${SYSTEMD_DIR}/cert-monitor@.service"
systemctl daemon-reload
systemctl enable --now "cert-monitor@${TARGET_USER}.service"
systemctl status --no-pager -n 10 "cert-monitor@${TARGET_USER}.service" || true
