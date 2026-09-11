#!/usr/bin/env bash
#
# =============================================================================
# Loghound uninstaller — the obvious name for `install.sh --uninstall`.
# =============================================================================
#
#   sudo ./install/uninstall.sh --dry-run    print the whole teardown, change nothing
#   sudo ./install/uninstall.sh              do it, asking before anything is deleted
#
# This is a WRAPPER, not a second implementation. Every line of teardown logic lives in
# install.sh, so there is exactly one copy of it to audit and exactly one copy to keep
# correct. A separate uninstaller would drift from the installer within one release, and
# the place it would drift is the list of things the installer creates — which is the one
# list that has to be right.
#
# Every flag install.sh accepts in uninstall mode is accepted here and passed straight
# through: --dry-run, --non-interactive, --yes, --prefix, --user. See `install.sh --help`.
#
# WHAT IT REMOVES, in the order install.sh documents in its own header: the units and both
# timers, the Opensolr indexes this installation provisioned (only on an explicit
# confirmation, and only after the platform confirms the account holds them), the vhost,
# the FPM pool, the command links, the credentials, and optionally the install tree and the
# service user.
#
# WHAT IT NEVER DOES: delete an index whose ownership it could not prove, reload a web
# server into a configuration that does not pass its own configtest, touch a source log
# file, or remove anything outside the install prefix that install.sh did not create.
#
# =============================================================================

set -euo pipefail

# The installer that does the work, resolved relative to this script so the pair can be run
# from a checkout, from the install tree, or through a symlink, and always find each other.
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="$SELF_DIR/install.sh"

if [[ ! -f "$INSTALLER" ]]; then
    printf 'ERROR install.sh is not next to this script (looked in %s).\n' "$SELF_DIR" >&2
    printf '      Run the uninstaller from the Loghound checkout or the install tree.\n' >&2
    exit 1
fi

# --uninstall is supplied here rather than expected from the caller, and install.sh
# tolerates being handed it twice, so `uninstall.sh --uninstall` behaves like `uninstall.sh`
# instead of failing on an argument the operator quite reasonably thought was needed.
if [[ -x "$INSTALLER" ]]; then
    exec "$INSTALLER" --uninstall "$@"
fi
exec bash "$INSTALLER" --uninstall "$@"
