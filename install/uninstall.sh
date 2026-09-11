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
# WHAT IT REMOVES, as eleven numbered steps printed in this order — the same eleven, under the
# same names, that the panel's own "Remove Loghound entirely" card runs as a job, because two
# front ends that disagree about what a teardown IS are two front ends nobody can check against
# each other. The list lives once, in Loghound\Setup\Teardown::STEPS, and a test asserts this
# script prints exactly it:
#
#    1. Services and timers
#    2. Proving your account owns these indexes
#    3. Deleting the Loghound indexes
#    4. Confirming they are gone from your account
#    5. Web server configuration
#    6. PHP-FPM pool
#    7. Command links and scheduler fragments
#    8. Credentials and local data
#    9. Install tree
#   10. System user
#   11. What was NOT removed
#
# Every heading carries its position, so a run watched over SSH always says where it is, and a
# step that bails out early still prints — as a skip — rather than leaving a gap somebody has to
# assume was fine.
#
# WHAT IT NEVER DOES: delete an index whose ownership it could not prove, call a delete
# accepted without re-reading the account listing to prove the name is gone, reload a web
# server into a configuration that does not pass its own configtest, touch a source log file,
# or remove anything outside the install prefix that install.sh did not create.
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
