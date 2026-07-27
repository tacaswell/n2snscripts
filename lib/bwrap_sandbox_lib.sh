#!/usr/bin/env bash
# bwrap_sandbox_lib.sh — Shared library for bubblewrap sandbox wrappers.
#
# Provides the common infrastructure for sandboxing CLI tools with bwrap:
#   - bwrap version detection and capability flags
#   - Dynamic mount helpers (deduplication, symlink resolution, npm detection)
#   - Git config include-path parsing
#   - Sandbox PATH construction
#   - Shell detection
#   - All shared bwrap mounts: base system, binary masking, /sys (cpu +
#     node topology, read-only), /etc, home tmpfs,
#     working directory, git config, pixi, ccache, npm, user bin, NSLS-II,
#     dynamic tool mounts, user-supplied extra paths (--ro-path / --rw-path)
#   - Environment variable framework (clean env + passthrough)
#   - Launch logic (dry-run printing and bwrap exec)
#
# The common wrapper front-end lives here:
#   - parse_wrapper_args_common — handles all shared flags (--help, --dry-run,
#     --exec, --init-auth, --github-tokens, --new-session, --ro-path, --rw-path);
#     delegates unknown flags to the wrapper's parse_wrapper_arg_hook
#   - resolve_tool_binary_named — resolves the tool binary and builds _TOOL_CMD
#     (verbatim --exec argv, or the tool binary)
#   - wrapper_show_help — prints the wrapper's help text and exits 0
#   - _persist_bind_wanted / init_auth stub helpers — --init-auth persistence
#
# Tool-specific wrapper scripts source this file and provide:
#   - parse_wrapper_arg_hook — handle any tool-specific flags (optional)
#   - Help text passed to wrapper_show_help
#   - Tool-specific path resolution, host directory creation, mounts, and env vars
#   - main() orchestrating the build sequence — must call build_extra_path_mounts
#     after build_dynamic_tool_mounts
#
# Usage (in tool wrapper scripts):
#   SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
#   source "${SCRIPT_DIR}/bwrap_sandbox_lib.sh"
#
# Requires: bwrap >= 0.4.0 (RHEL 8)
#   - 0.4.0: base functionality
#   - 0.5.0+: --clearenv (fallback: manual --unsetenv for each host var)
#   - 0.6.3+: bind over ro-bind (fallback: skip binary masking)

# Guard against double-sourcing.
[[ -n "${_BWRAP_SANDBOX_LIB_SOURCED:-}" ]] && return 0
_BWRAP_SANDBOX_LIB_SOURCED=1

# ═══════════════════════════════════════════════════════════════════
# Global state
# ═══════════════════════════════════════════════════════════════════

# Wrapper control flags (set by the shared parse_wrapper_args_common)
# shellcheck disable=SC2034  # used by tool wrappers that source this library
DRY_RUN=0
# --exec state.  HAVE_EXEC=1 when the user passed --exec; EXEC_CMD then holds
# the verbatim remaining argv to run inside the sandbox instead of the tool.
# (Replaces the old TEST_CMD string, which was word-split with `read -ra` and
# therefore mangled any quoted --exec command.)
# shellcheck disable=SC2034  # used by tool wrappers that source this library
HAVE_EXEC=0
# shellcheck disable=SC2034  # used by tool wrappers that source this library
EXEC_CMD=()
# shellcheck disable=SC2034  # used by tool wrappers that source this library
SHOW_HELP=0
# shellcheck disable=SC2034  # used by print_dry_run and launch_sandbox
TOOL_ARGS=()
# shellcheck disable=SC2034  # set by tool wrappers when --new-session is requested
FORCE_NEW_SESSION=0
# Wrapper flags shared by every bw* wrapper (all four implement --init-auth and
# --github-tokens); set by parse_wrapper_args_common.
# shellcheck disable=SC2034  # used by tool wrappers that source this library
INIT_AUTH=0
# shellcheck disable=SC2034  # used by tool wrappers that source this library
FORWARD_GH_TOKENS=0
# Number of args consumed by the wrapper-specific hook (see
# parse_wrapper_args_common / parse_wrapper_arg_hook).
_ARG_SHIFT=0

# Extra user-supplied paths to mount into the sandbox.
# Populated by tool-specific parse_wrapper_args via --ro-path / --rw-path.
# Validated and mounted by build_extra_path_mounts.
# shellcheck disable=SC2034  # used by tool wrappers that source this library
EXTRA_RO_PATHS=()
# shellcheck disable=SC2034  # used by tool wrappers that source this library
EXTRA_RW_PATHS=()

# Tool binary (set by tool-specific resolve_tool_binary)
_TOOL_BIN=""
_TOOL_CMD=()

# bwrap construction
BWRAP_ARGS=()
declare -A _MOUNTED_PREFIXES=()
_EXTRA_PATH_DIRS=()

# Cached result of `npm prefix -g` (resolved at most once per run).
# _NPM_PREFIX_RESOLVED flips to 1 after the first lookup; _NPM_PREFIX holds
# the value (empty string if npm is absent or the lookup failed).
_NPM_PREFIX=""
_NPM_PREFIX_RESOLVED=0

# Sandbox environment
SANDBOX_PATH=""
SANDBOX_SHELL=""

# bwrap capability flags (set by detect_bwrap_capabilities)
HAS_ARGS_FD=0
HAS_CLEARENV=0
HAS_BIND_OVER_RO=0

# Kernel capability flags (set by detect_kernel_capabilities)
KERNEL_HAS_TIOCSTI_CAP_GUARD=0

# Git include tracking (used by parse_git_includes).  Parallel arrays:
# GIT_INCLUDE_PATHS holds the logical include paths (what git opens, and
# therefore the bind DESTINATION); GIT_INCLUDE_TARGETS holds each path's
# canonical resolution (the bind SOURCE).  They differ when an include is a
# symlink or sits under a symlinked directory (e.g. dotfiles-managed
# ~/.git_work_config -> ~/.dotfiles/git/...).
declare -A _GIT_INCLUDE_SEEN=()
GIT_INCLUDE_PATHS=()
GIT_INCLUDE_TARGETS=()

# Working directory state (set by build_workdir_mount)
_BIND_DIR=""
_GIT_ROOT=""

# Canonical home and derived path-safety data (set by resolve_common_paths).
# _HOME is the logical $HOME; _HOME_CANON is its readlink -f form.  On hosts
# where home is reached through a symlink (NFS/automount) these differ, and
# both must be consulted because candidate paths are canonicalized before the
# safety check.  _HOME_ROOTS and _BLOCKED_PREFIXES are precomputed once (to
# avoid per-check readlink forks) and consumed by _check_path_safe.
_HOME=""
_HOME_CANON=""
_PWD=""
# Guarded username (set by resolve_common_paths).  $USER may be unset under
# `set -u` in cron/CI contexts, so fall back to `id -un`.
_USER=""
declare -a _HOME_ROOTS=()
declare -a _BLOCKED_PREFIXES=()

# ═══════════════════════════════════════════════════════════════════
# Shared helper functions
# ═══════════════════════════════════════════════════════════════════

# _version_ge A B
#   Return 0 (true) if dotted version A is greater than or equal to B.
#   Uses `sort -V` (GNU coreutils, bash 4.1-era and later) so that
#   multi-component versions like 0.11.0 sort correctly against 0.5.0 —
#   a plain string/integer comparison would mis-order 0.11 vs 0.5.
_version_ge() {
    local a="$1" b="$2"
    [[ "${a}" == "${b}" ]] && return 0
    # If the lexicographically-smallest version (per sort -V) is B, then A > B.
    [[ "$(printf '%s\n%s\n' "${a}" "${b}" | sort -V | head -n1)" == "${b}" ]]
}

# Feature detection by parsing the version string — much cheaper than
# grepping --help.
#
# Version history:
#   0.1.7 - added --args FD (NUL-separated args from an inherited fd)
#   0.5.0 - added --clearenv
#   0.6.3 - bind over ro-bind works (can mask binaries inside /usr)
detect_bwrap_capabilities() {
    local _bwrap_ver
    _bwrap_ver="$(bwrap --version)"
    _bwrap_ver="${_bwrap_ver##* }"            # "bubblewrap 0.11.0" -> "0.11.0"

    # --args FD: Read NUL-separated arguments from an inherited file descriptor
    # (added in 0.1.7, well before the 0.4.0 floor).  This keeps secrets out of
    # /proc/<pid>/cmdline: forwarded credentials (API keys, tokens) are placed
    # on bwrap's argv via --setenv, so a resident bwrap process exposes them to
    # any local user via `ps auxww` or /proc/<pid>/cmdline.  Passing BWRAP_ARGS
    # through --args FD instead of argv closes the leak.
    # Fallback: pass arguments via argv (residual exposure on ancient hosts).
    HAS_ARGS_FD=0
    if _version_ge "${_bwrap_ver}" "0.1.7"; then HAS_ARGS_FD=1; fi

    # --clearenv: Start with an empty environment (added in 0.5.0)
    # Fallback: manually unset all host env vars with --unsetenv
    HAS_CLEARENV=0
    if _version_ge "${_bwrap_ver}" "0.5.0"; then HAS_CLEARENV=1; fi

    # Bind over ro-bind: ability to bind-mount on top of a read-only bind
    # mount (e.g., masking /usr/bin/ssh after --ro-bind /usr /usr).
    # This works in 0.6.3+; earlier versions fail with "Permission denied".
    # Fallback: skip binary masking (security reduction — tools remain accessible)
    HAS_BIND_OVER_RO=0
    if _version_ge "${_bwrap_ver}" "0.6.3"; then HAS_BIND_OVER_RO=1; fi
}

# Detect kernel-level security features that affect bwrap argument choice.
#
# TIOCSTI capability guard (Linux 5.14+):
#   On kernels >= 5.14, the TIOCSTI ioctl requires CAP_SYS_ADMIN on any
#   tty that is not the process's own controlling terminal.  bwrap drops
#   all capabilities unconditionally, so TIOCSTI is already blocked at
#   the kernel level — making --new-session redundant for that threat.
#
#   On older kernels (e.g. RHEL 8 / 4.18), --new-session is the only
#   guard against TIOCSTI injection and must be kept.
#
#   We omit --new-session when this guard is present so that SIGWINCH
#   (terminal resize) is delivered correctly from tmux and other
#   multiplexers to the sandboxed process.
detect_kernel_capabilities() {
    local _kver
    _kver="$(uname -r)"
    _kver="${_kver%%-*}"            # strip suffix e.g. "5.14.0-427.el9" -> "5.14.0"

    KERNEL_HAS_TIOCSTI_CAP_GUARD=0
    if _version_ge "${_kver}" "5.14"; then KERNEL_HAS_TIOCSTI_CAP_GUARD=1; fi
}

detect_shell() {
    SANDBOX_SHELL="$(command -v bash 2> /dev/null || echo /bin/sh)"
}

# _expand_leading_tilde VALUE
#   Expand only a *leading* tilde in VALUE and echo the result:
#     "~"        -> $HOME
#     "~/path"   -> $HOME/path
#     "~user"    -> that user's home directory (resolved via getent passwd)
#     "~user/p"  -> that user's home directory + /p
#     (no leading ~) -> VALUE unchanged
#   Returns 0 on success; returns 1 (echoing nothing) if a ~user reference
#   cannot be resolved.  A blind ${VALUE/#\~/${_HOME}} substitution is WRONG:
#   it turns "~alice/foo" into "${HOME}alice/foo", silently corrupting the path.
_expand_leading_tilde() {
    local value="$1"
    # The "~" / "~/" case patterns match a *literal* leading tilde in the input;
    # we are not asking the shell to expand a tilde here (SC2088 false positive).
    # shellcheck disable=SC2088
    case "${value}" in
        "~")
            printf '%s' "${_HOME}"
            ;;
        "~/"*)
            printf '%s' "${_HOME}/${value#\~/}"
            ;;
        "~"*)
            # ~user or ~user/subpath — resolve the named user's home dir.
            local _rest="${value#\~}"           # "user" or "user/subpath"
            local _user="${_rest%%/*}"          # "user"
            local _subpath=""
            [[ "${_rest}" == */* ]] && _subpath="/${_rest#*/}"
            local _uhome
            _uhome="$(getent passwd "${_user}" 2> /dev/null | cut -d: -f6)"
            [[ -n "${_uhome}" ]] || return 1
            printf '%s' "${_uhome}${_subpath}"
            ;;
        *)
            printf '%s' "${value}"
            ;;
    esac
    return 0
}

# ── Dynamic mount helpers ────────────────────────────────────────
# _MOUNTED_PREFIXES: tracks directory trees already covered by a bwrap
# bind so we never emit duplicate (or redundant sub-path) mounts.
# Keys are canonical paths; value is always 1.
# Pre-populated with unconditional mounts in build_dynamic_tool_mounts.

# _resolve_npm_prefix
#   Populate the _NPM_PREFIX / _NPM_PREFIX_RESOLVED globals with the npm global
#   prefix (`npm prefix -g`), forking node at most once per run.  _NPM_PREFIX is
#   the empty string if npm is absent or the lookup fails.
#
#   IMPORTANT: this MUST be called in a non-subshell context (not inside a
#   $(...) command substitution) so the globals it sets persist.  The previous
#   design echoed the value and was always called via $(...), so the "resolved"
#   flag was set in a subshell and lost — forking node on *every* lookup, and
#   creating ~/.npm/_logs on the host even under --dry-run.  Callers now invoke
#   this directly and then read ${_NPM_PREFIX}.
#
#   `npm prefix -g` writes a logfile under $npm_config_cache/_logs (default
#   ~/.npm/_logs).  To keep --dry-run (and every run) free of that host-state
#   mutation, the cache is pointed at a throwaway temp dir that is removed
#   immediately after the call.
_resolve_npm_prefix() {
    [[ "${_NPM_PREFIX_RESOLVED}" -eq 1 ]] && return 0
    _NPM_PREFIX_RESOLVED=1
    _NPM_PREFIX=""
    command -v npm > /dev/null 2>&1 || return 0

    local _npm_tmp
    _npm_tmp="$(mktemp -d 2> /dev/null || true)"
    if [[ -n "${_npm_tmp}" ]]; then
        _NPM_PREFIX="$(npm_config_cache="${_npm_tmp}" npm prefix -g 2> /dev/null || true)"
        rm -rf "${_npm_tmp}"
    else
        _NPM_PREFIX="$(npm prefix -g 2> /dev/null || true)"
    fi
}

# _emit_home_intermediate_dirs DIR [MODE]
#   Emit `--dir` BWRAP_ARGS for the ancestor components of DIR that live
#   under $HOME, so the eventual bind mount point exists inside the tmpfs
#   $HOME (which starts out with no subdirectories).  No-op when DIR is not
#   under $HOME.
#
#   MODE:
#     "ancestors" (default) — emit --dir for every component strictly
#                  BETWEEN $HOME and DIR; DIR itself is left out because it
#                  will be the bind mount point.
#     "inclusive" — also emit --dir for DIR itself (use when DIR is a parent
#                  directory that must exist, e.g. the directory holding a
#                  file bind, or a read-write directory bind point).
_emit_home_intermediate_dirs() {
    local dir="$1" mode="${2:-ancestors}"
    # Home may be symlinked (NFS/automount): a canonicalized bind target can
    # sit under _HOME_CANON rather than the logical _HOME.  Match against both.
    local _home_base
    if [[ "${dir}" == "${_HOME}"/* ]]; then
        _home_base="${_HOME}"
    elif [[ -n "${_HOME_CANON}" && "${dir}" == "${_HOME_CANON}"/* ]]; then
        _home_base="${_HOME_CANON}"
    else
        return 0
    fi
    local _rel="${dir#"${_home_base}"/}"
    local _accum="${_home_base}"
    local _parts _i _last
    IFS='/' read -ra _parts <<< "${_rel}"
    if [[ "${mode}" == "inclusive" ]]; then
        _last=${#_parts[@]}
    else
        _last=$((${#_parts[@]} - 1))
    fi
    for ((_i = 0; _i < _last; _i++)); do
        _accum="${_accum}/${_parts[$_i]}"
        BWRAP_ARGS+=(--dir "${_accum}")
    done
}

# _mount_ro_dir_if_needed DIR
#   Bind-mount DIR read-only into the sandbox, unless it (or a parent
#   tree) is already registered in _MOUNTED_PREFIXES.  If the bind is
#   actually emitted, DIR is added to _MOUNTED_PREFIXES so future calls
#   with the same path or a sub-path are no-ops.
#   Handles intermediate --dir entries for paths under $HOME.
#   Calls _check_path_safe before emitting any mount — aborts if DIR
#   resolves into a blocked path (e.g. a tool binary that symlinks into
#   ~/.ssh or a misconfigured npm prefix pointing at $HOME).
_mount_ro_dir_if_needed() {
    local dir="$1"
    [[ -d "${dir}" ]] || return 0

    # Check whether dir is already covered by a registered prefix.  The walk
    # tests every ancestor including "/" itself so a (theoretical) registered
    # "/" prefix would de-duplicate correctly.
    local check="${dir}"
    while :; do
        if [[ -n "${_MOUNTED_PREFIXES["${check}"]:-}" ]]; then
            return 0  # already covered
        fi
        [[ "${check}" == "/" ]] && break
        check="${check%/*}"
        [[ -z "${check}" ]] && check="/"
    done

    # Safety check before emitting the mount.  DIR is already a real
    # directory path (callers pass dirname() of a resolved binary or a
    # known path), so no additional readlink -f is needed.
    _check_path_safe "${dir}" "dynamic mount"

    # Create intermediate --dir entries for paths under $HOME (the
    # tmpfs $HOME has no subdirectories yet).  DIR is the bind mount point,
    # so only its ancestors are pre-created.
    _emit_home_intermediate_dirs "${dir}"

    BWRAP_ARGS+=(--ro-bind "${dir}" "${dir}")
    _MOUNTED_PREFIXES["${dir}"]=1
}

# resolve_and_mount_tool BINARY_PATH
#   Given an absolute path to a binary (as returned by command -v),
#   mount its on-PATH directory AND — if it is a symlink — the real
#   binary's directory.  Both are passed through _mount_ro_dir_if_needed
#   so deduplication is automatic.
#   The on-PATH bin directory is added to _EXTRA_PATH_DIRS.
#   Special case: if the real binary resolves into the npm global prefix,
#   the entire prefix tree is mounted via _mount_npm_global_prefix (which
#   subsumes the narrow bin/ dir) rather than a narrow bind.
resolve_and_mount_tool() {
    local bin_path="$1"
    [[ -n "${bin_path}" ]] || return 0

    local cmd_dir real_path npm_prefix cmd_dir_canon
    cmd_dir="$(dirname "${bin_path}")"

    # Record the on-PATH dir for SANDBOX_PATH so the tool remains reachable via
    # the same name inside the sandbox.  The tool is invoked by its LOGICAL path
    # (_TOOL_BIN = `command -v NAME`), and it is mounted below at that same
    # logical path, so PATH must carry the logical dir too.
    _EXTRA_PATH_DIRS+=("${cmd_dir}")

    # Path-safety must be judged on the canonical target, not the logical path:
    # a symlinked on-PATH directory whose target is a blocked subtree (e.g.
    # ~/bin -> ~/.ssh) would otherwise slip a blocked tree past _check_path_safe.
    # We validate the canonical target here, but still MOUNT the logical cmd_dir
    # below so the tool stays reachable at the path the sandbox invokes it by
    # (mounting the canonical dir instead would leave _TOOL_BIN's logical path
    # absent in the tmpfs $HOME).  _check_path_safe dies on a blocked path.
    cmd_dir_canon="$(readlink -f "${cmd_dir}" 2> /dev/null || printf '%s' "${cmd_dir}")"
    _check_path_safe "${cmd_dir_canon}" "tool directory"

    if [[ -L "${bin_path}" ]]; then
        real_path="$(readlink -f "${bin_path}")"
        _resolve_npm_prefix
        npm_prefix="${_NPM_PREFIX}"
        if [[ -n "${npm_prefix}" ]] && [[ "${real_path}" == "${npm_prefix}"/* ]]; then
            # npm-installed: mount the whole prefix so lib/node_modules is reachable.
            # Also mount the on-PATH directory the symlink lives in: it may be an
            # otherwise-unmounted dir (e.g. ~/.local/bin/claude -> npm prefix), and
            # without it the symlink source path is absent inside the sandbox.
            _mount_ro_dir_if_needed "${cmd_dir}"
            _mount_npm_global_prefix "${npm_prefix}"
            return 0
        fi
        _mount_ro_dir_if_needed "${cmd_dir}"
        # dirname of the real_path is already canonical (real_path came from
        # readlink -f), so no additional canonicalization needed here.
        _mount_ro_dir_if_needed "$(dirname "${real_path}")"
    else
        # Non-symlink binary: mount its directory.  _mount_ro_dir_if_needed
        # de-duplicates internally, so no prior prefix check is needed here.
        _mount_ro_dir_if_needed "${cmd_dir}"
    fi
}

# _mount_npm_global_prefix [PREFIX]
#   Mount the entire npm global prefix tree read-only and add its bin/
#   subdirectory to _EXTRA_PATH_DIRS.  PREFIX defaults to `npm prefix -g`.
#   Aborts if the resolved prefix is a blocked path — e.g. when npm has
#   been misconfigured with `npm config set prefix ~` (a common mistake
#   documented in npm's own install guide), which would expose the entire
#   home directory read-only inside the sandbox.
_mount_npm_global_prefix() {
    local npm_prefix="${1:-}"
    if [[ -z "${npm_prefix}" ]]; then
        _resolve_npm_prefix
        npm_prefix="${_NPM_PREFIX}"
    fi
    [[ -n "${npm_prefix}" ]] && [[ -d "${npm_prefix}" ]] || return 0

    # Canonicalise before the safety check so symlinks in the prefix path
    # are resolved (npm itself may return a non-canonical path on some systems).
    local npm_prefix_canon
    npm_prefix_canon="$(readlink -f "${npm_prefix}" 2> /dev/null || echo "${npm_prefix}")"
    _check_path_safe "${npm_prefix_canon}" "npm global prefix"

    _mount_ro_dir_if_needed "${npm_prefix_canon}"
    _EXTRA_PATH_DIRS+=("${npm_prefix_canon}/bin")
}

# ── Git include parser ───────────────────────────────────────────

parse_git_includes() {
    local config_file="$1"
    [[ -f "${config_file}" ]] || return 0

    # Git resolves relative include paths relative to the location of
    # the config file (the symlink path, NOT the resolved target).
    local config_dir="${config_file%/*}"

    # Extract include path values.  Pure bash — no grep/sed/xargs subprocesses.
    #
    # A `path = ...` key is only an include directive when it sits inside an
    # [include] section.  Git's parser is section-scoped; without tracking the
    # current section, a `path =` key in an unrelated section such as
    # [difftool "x"] or [delta] is mis-read as an include, which would mount an
    # arbitrary path — or hard-exit build_git_mounts if that path lands in a
    # blocked prefix (e.g. a legal difftool.path).
    #
    # [includeIf "<cond>"] conditional includes: the referenced files are
    # mounted unconditionally without evaluating the condition here.  Git inside
    # the sandbox sees the real gitdir (the repo is bind-mounted at the same
    # path), so it evaluates conditions correctly at runtime and silently skips
    # files whose condition does not match.  Implementing gitdir/onbranch/
    # hasconfig glob semantics in pure bash would be complex and fragile;
    # mounting a superset is safe because every file still passes the same
    # _check_path_safe guard as plain [include] files.
    local line _section _section_name path_val
    local in_include=0
    while IFS= read -r line || [[ -n "${line}" ]]; do
        # Section header, e.g. "[include]", "  [includeIf \"gitdir:~/w/\"]",
        # "[difftool \"meld\"]".  Update the current-section flag and move on.
        if [[ "${line}" =~ ^[[:space:]]*\[([^]]+)\] ]]; then
            _section="${BASH_REMATCH[1]}"
            # Strip any trailing subsection (quoted part) and lowercase — git
            # section names are case-insensitive.
            _section_name="${_section%%[[:space:]]*}"
            _section_name="${_section_name,,}"
            if [[ "${_section_name}" == "include" || "${_section_name}" == "includeif" ]]; then
                in_include=1
            else
                in_include=0
            fi
            continue
        fi

        # Only honor `path =` inside an [include] section.
        [[ "${in_include}" -eq 1 ]] || continue
        [[ "${line}" =~ ^[[:space:]]*path[[:space:]]*=[[:space:]]*(.*) ]] || continue
        path_val="${BASH_REMATCH[1]}"

        # Trim trailing whitespace
        path_val="${path_val%"${path_val##*[![:space:]]}"}"
        [[ -z "${path_val}" ]] && continue

        # Strip inline comments and surrounding double-quotes.  Git treats `#`
        # and `;` as comment starts (the rest of the line is ignored) UNLESS the
        # character is inside a quoted string.  Git also strips surrounding
        # double-quotes and interprets backslash escapes (`\"` and `\\`) inside
        # those quotes.
        #
        # Minimal implementation: handle the two most common cases:
        #   1. Whole-value double-quoted:  path = "/real/path"
        #   2. Unquoted trailing comment:  path = /real/path ; note
        #
        # LIMITATION: mixed quotes/comments (e.g. path = "/path with ; semicolon")
        # are not fully parsed — the `;` inside the quoted string would still
        # trigger comment stripping here, which is WRONG per git's rules.  Full
        # git-compatible quote/escape parsing is out of scope for this pure-bash
        # parser.  The existing -e check fails closed: an incorrectly-stripped
        # path fails the existence test and the include is silently dropped (no
        # over-mount), so the tool runs but without that include's settings.
        #
        # Strip surrounding double-quotes if present (whole-value quoted case).
        # The pattern [[ "${path_val}" == \"*\" ]] matches a value that both
        # starts and ends with a literal double-quote.
        if [[ "${path_val}" == \"*\" ]]; then
            # Strip leading and trailing quotes.
            path_val="${path_val#\"}"
            path_val="${path_val%\"}"
            # Handle git's backslash escapes minimally: \\ -> \, \" -> ".
            # (Full git escape parsing also covers \n, \t, \b, but paths do not
            # typically use those; we handle only the two that appear in practice.)
            path_val="${path_val//\\\\/\\}"
            path_val="${path_val//\\\"/\"}"
        else
            # Unquoted: strip an inline ` #` or ` ;` comment (a space followed by
            # the comment char — git requires the leading space).  We match
            # " #" or " ;" and discard everything from that point onward, then
            # trim trailing whitespace again (the comment may have had leading
            # space).  This is safe for the common "path = /real/path ; note" case.
            #
            # KNOWN ISSUE: a `;` or `#` that is part of an unquoted path with no
            # leading space (e.g. path = /path;with;semicolons) will be incorrectly
            # treated as a comment start.  Such paths are exotic (and likely
            # unintentional in git config); the -e check below will catch the
            # resulting malformed path and skip the include.
            if [[ "${path_val}" =~ ^([^#\;]*)[[:space:]][#\;] ]]; then
                path_val="${BASH_REMATCH[1]}"
                # Trim trailing whitespace from the captured part.
                path_val="${path_val%"${path_val##*[![:space:]]}"}"
            fi
        fi
        [[ -z "${path_val}" ]] && continue

        # Expand a leading ~/ (or ~user/).  Skip the include if a ~user
        # reference cannot be resolved rather than silently corrupting it.
        path_val="$(_expand_leading_tilde "${path_val}")" || continue

        # Resolve relative paths (relative to the config file's directory)
        if [[ "${path_val}" != /* ]]; then
            path_val="${config_dir}/${path_val}"
        fi

        # Canonicalize for the bind SOURCE.  readlink -f resolves the file
        # itself AND any symlinked ancestor directories (a dotfiles-managed
        # include like ~/.git_work_config -> ~/.dotfiles/git/... is the common
        # case).  The LOGICAL path stays the bind DESTINATION: git opens the
        # include at the path written in the config, and inside the tmpfs
        # $HOME the host's symlink does not exist — binding at the canonical
        # path would leave the logical path dangling.
        local resolved
        resolved="$(readlink -f "${path_val}" 2> /dev/null || echo "${path_val}")"

        # Deduplicate on the logical path (the mount destination).
        if [[ -e "${resolved}" ]] && [[ -z "${_GIT_INCLUDE_SEEN["${path_val}"]:-}" ]]; then
            _GIT_INCLUDE_SEEN["${path_val}"]=1
            GIT_INCLUDE_PATHS+=("${path_val}")
            GIT_INCLUDE_TARGETS+=("${resolved}")
        fi
    done < "${config_file}"
}

# Parse the standard git config files for include directives.
parse_all_git_includes() {
    if [[ -f "${_HOME}/.gitconfig" ]]; then
        parse_git_includes "${_HOME}/.gitconfig"
    fi
    if [[ -f "${XDG_CONFIG_HOME}/git/config" ]]; then
        parse_git_includes "${XDG_CONFIG_HOME}/git/config"
    fi
}

# ── Env var passthrough helpers ──────────────────────────────────

pass_through_if_set() {
    local var_name="$1"
    local var_val="${!var_name:-}"
    if [[ -n "${var_val}" ]]; then
        BWRAP_ARGS+=(--setenv "${var_name}" "${var_val}")
    fi
}

# forward_env_by_prefix PREFIX
#   Iterate over all exported environment variables whose names start with
#   PREFIX and append a --setenv entry to BWRAP_ARGS for each one found.
#   Uses the safe `while IFS= read -r` form so variable names containing
#   unusual characters (e.g. BASH_FUNC_module%%) are handled correctly.
#
#   Values are passed through as-is; print_dry_run redacts any names that
#   match the sensitive patterns in _is_secret_env_var.
#
#   Example:
#     forward_env_by_prefix GH_TOKEN_    # forwards GH_TOKEN_NSLS2, GH_TOKEN_PERSONAL, …
#     forward_env_by_prefix COPILOT_PROVIDER_
forward_env_by_prefix() {
    local _prefix="$1"
    local _key
    while IFS= read -r _key; do
        if [[ "${_key}" == "${_prefix}"* ]]; then
            BWRAP_ARGS+=(--setenv "${_key}" "${!_key}")
        fi
    done < <(compgen -e)
}

# ── Shared wrapper front-end (arg parsing, tool resolution, help) ─
# These helpers factor the near-identical boilerplate out of the four bw*
# wrappers so that the --exec, --help, and --init-auth fixes live in one place.

# parse_wrapper_args_common "$@"
#   Parse the flags common to every bw* wrapper and populate TOOL_ARGS with the
#   remaining passthrough arguments.  For any flag it does not recognize, it
#   calls the wrapper-provided hook `parse_wrapper_arg_hook "$@"`, which must set
#   the global _ARG_SHIFT to the number of args it consumed (0 = not a
#   wrapper flag → stop parsing; the rest is passed through to the tool).
#
#   Common flags:
#     --help/-h, --dry-run, --exec (consumes the REST of argv verbatim),
#     --init-auth, --github-tokens, --new-session, --ro-path, --rw-path.
#
#   --exec consumes every remaining argument verbatim into EXEC_CMD; there is
#   no quote re-splitting, so `--exec bash -c 'env | sort'` runs exactly that
#   argv inside the sandbox.
parse_wrapper_args_common() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help | -h)
                # shellcheck disable=SC2034  # read by the wrapper's main()
                SHOW_HELP=1
                shift
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --exec)
                shift
                if [[ $# -lt 1 ]]; then
                    echo "Error: --exec requires a command to run." >&2
                    exit 1
                fi
                HAVE_EXEC=1
                EXEC_CMD=("$@")
                shift $#
                ;;
            --init-auth)
                INIT_AUTH=1
                shift
                ;;
            --github-tokens)
                # shellcheck disable=SC2034  # read by the wrapper's build_*_env
                FORWARD_GH_TOKENS=1
                shift
                ;;
            --new-session)
                FORCE_NEW_SESSION=1
                shift
                ;;
            --ro-path)
                if [[ $# -lt 2 ]]; then
                    echo "Error: --ro-path requires a path argument." >&2
                    exit 1
                fi
                EXTRA_RO_PATHS+=("$2")
                shift 2
                ;;
            --rw-path)
                if [[ $# -lt 2 ]]; then
                    echo "Error: --rw-path requires a path argument." >&2
                    exit 1
                fi
                EXTRA_RW_PATHS+=("$2")
                shift 2
                ;;
            *)
                # Delegate to the wrapper's tool-specific flag handler.  If it
                # does not recognize the token, parsing stops and the remainder
                # is passed through to the tool.
                _ARG_SHIFT=0
                parse_wrapper_arg_hook "$@"
                if [[ "${_ARG_SHIFT}" -gt 0 ]]; then
                    shift "${_ARG_SHIFT}"
                else
                    break
                fi
                ;;
        esac
    done
    # shellcheck disable=SC2034  # consumed by library's print_dry_run/launch_sandbox
    TOOL_ARGS=("$@")
}

# Default no-op tool-specific flag hook.  Wrappers with extra flags (bwclaude,
# bwcodex) override this; wrappers without (bwcopilot, bwopencode) inherit it.
parse_wrapper_arg_hook() {
    _ARG_SHIFT=0
}

# resolve_tool_binary_named NAME [HINT_LINE...]
#   Resolve the absolute path to tool NAME on the host into _TOOL_BIN, and set
#   _TOOL_CMD to the verbatim --exec argv (if --exec was given) or the tool
#   binary itself.  Exits 1 with NAME plus any HINT_LINEs if NAME is not found.
resolve_tool_binary_named() {
    local _name="$1"
    shift
    _TOOL_BIN="$(command -v "${_name}" 2> /dev/null || true)"
    if [[ -z "${_TOOL_BIN}" ]]; then
        echo "Error: '${_name}' not found in PATH." >&2
        local _hint
        for _hint in "$@"; do
            echo "${_hint}" >&2
        done
        exit 1
    fi

    if [[ "${HAVE_EXEC}" -eq 1 ]]; then
        _TOOL_CMD=("${EXEC_CMD[@]}")
    else
        _TOOL_CMD=("${_TOOL_BIN}")
    fi
}

# wrapper_show_help HELP_TEXT
#   Print the wrapper's own help text and exit 0.  Deliberately does NOT run the
#   tool or require credentials/config: `--help` must always succeed, even when
#   the tool is not installed or no API key/config is present.  (The tool's own
#   options remain reachable via, e.g., `bwclaude --exec claude --help`.)
wrapper_show_help() {
    printf '%s\n' "$1"
    exit 0
}

# _persist_bind_wanted PATH
#   True if PATH exists OR we are in --dry-run + --init-auth mode.  In the
#   latter case a real run would have created the stub file and bound it, so we
#   emit the bind for dry-run fidelity even though the stub was not created.
_persist_bind_wanted() {
    [[ -e "$1" ]] || { [[ "${INIT_AUTH}" -eq 1 ]] && [[ "${DRY_RUN}" -eq 1 ]]; }
}

# ── Path safety validation ───────────────────────────────────────

# _is_prefix_of A B
#   Returns 0 (true) if B == A or B starts with A/ (A is a parent of B).
#   Special-cases A="/" because the pattern "${A}/"* would become "//*"
#   which never matches any real path.
_is_prefix_of() {
    local a="$1" b="$2"
    # a="/" matches every absolute path; otherwise b must equal a or sit
    # directly beneath it (a/...).
    [[ "${a}" == "/" || "${b}" == "${a}" || "${b}" == "${a}/"* ]]
}

# _check_path_safe CANON CONTEXT
#   Assert that the already-resolved canonical path CANON is safe to mount
#   into the sandbox.  Exits 1 with a descriptive error if it is not.
#
#   CANON   : absolute, symlink-free path (output of readlink -f).
#   CONTEXT : short label used in error messages, e.g. "--ro-path",
#             "--rw-path", or "working directory".
#
#   Must be called AFTER resolve_common_paths so that XDG_DATA_HOME is set.
#   All build_* and validate_* functions satisfy this — they are called from
#   main() after resolve_common_paths.
#
#   Blocked conditions (all checked against the canonical path):
#     - CANON is $HOME or an ancestor of $HOME (/, /home, etc.) — would
#       expose the entire home tree inside the sandbox.
#     - CANON is inside any of the following sensitive subtrees:
#
#       SSH / GPG / cloud keys
#         ~/.ssh/          private keys and known_hosts
#         ~/.gnupg/        GPG private keys and keyrings
#         ~/.aws/          AWS credentials and config
#         ~/.kube/         Kubernetes cluster credentials (tokens, certs)
#         ~/.docker/       Docker registry auth (config.json with tokens)
#
#       Package-manager credentials
#         ~/.netrc         cleartext credentials for pip/git/curl/wget
#                          (used by pip, uv, curl, git-credential-netrc)
#         ~/.pypirc        twine/flit PyPI upload tokens and passwords
#         ~/.rattler/      pixi/rattler conda channel auth tokens
#                          (default path: ~/.rattler/credentials.json;
#                           can be overridden with RATTLER_AUTH_FILE)
#         ~/.yarnrc        yarn classic (v1) registry auth tokens
#         ~/.yarnrc.yml    yarn berry (v2+) per-user registry auth tokens
#         ~/.yarn/         yarn berry global config directory
#         $XDG_DATA_HOME/uv/credentials
#                          uv per-index auth tokens (`uv auth login`);
#                          default path ~/.local/share/uv/credentials
#                          (confirmed via `uv auth dir`)
#
#       Password managers
#         ~/.password-store    pass/gopass GPG-encrypted secret store
#         ~/.config/1Password  1Password CLI session and config
#         ~/.config/op         1Password CLI (alternate config path)
#
#       GitHub CLI
#         ~/.config/gh/    GitHub CLI auth tokens (hosts.yml, etc.)
#                          Note: bwcopilot intentionally mounts hosts.yml
#                          from this directory via build_gh_auth_mount,
#                          which bypasses this check by design — the block
#                          prevents USER-supplied paths (--ro-path) from
#                          reaching gh credentials in other wrappers.
#
#       System
#         /root            root's home directory
#         /etc/shadow      system password hashes
#         /etc/sudoers     sudo policy
#         /etc/sudoers.d/  sudo policy fragments
#
#   Does NOT check existence — the caller is responsible for that.
#
#   NOTE: this consults the precomputed _HOME_ROOTS and _BLOCKED_PREFIXES
#   globals, which _build_blocked_prefixes populates from resolve_common_paths
#   in BOTH logical and canonical form.  A canonical candidate therefore cannot
#   slip past a blocked prefix that was expressed with the logical home.
_check_path_safe() {
    local canon="$1"
    local context="$2"

    # ── Ancestor-of-home check ───────────────────────────────────
    # Reject if canon IS $HOME or is a directory that contains $HOME
    # (i.e. /, /home, the username's parent dir, etc.).  Checked against both
    # the logical and canonical home so a symlinked home cannot be bypassed.
    local _home_root
    for _home_root in "${_HOME_ROOTS[@]}"; do
        if _is_prefix_of "${canon}" "${_home_root}"; then
            echo "Error: ${context} '${canon}' is \$HOME or an ancestor of \$HOME." >&2
            echo "       Refusing to mount — this would expose the entire home tree." >&2
            exit 1
        fi
    done

    # ── Sensitive-subtree checks ─────────────────────────────────
    local _blocked_prefix
    for _blocked_prefix in "${_BLOCKED_PREFIXES[@]}"; do
        if _is_prefix_of "${_blocked_prefix}" "${canon}"; then
            echo "Error: ${context} '${canon}' is inside the blocked path '${_blocked_prefix}'." >&2
            echo "       Refusing to mount." >&2
            exit 1
        fi
    done
}

# _build_blocked_prefixes
#   Populate the _HOME_ROOTS and _BLOCKED_PREFIXES globals consumed by
#   _check_path_safe.  Every home-derived blocked prefix is registered in both
#   its logical form (built from _HOME) and its canonical form (built from
#   _HOME_CANON); likewise /root and $XDG_DATA_HOME are registered in both
#   logical and canonical form.  Computed once (three readlink -f forks total)
#   so _check_path_safe never forks per candidate.
#
#   Must be called by resolve_common_paths after XDG_DATA_HOME is set and
#   before any function that invokes _check_path_safe.
_build_blocked_prefixes() {
    # Home roots for the ancestor-of-home check (logical + canonical).
    _HOME_ROOTS=("${_HOME}")
    [[ "${_HOME_CANON}" != "${_HOME}" ]] && _HOME_ROOTS+=("${_HOME_CANON}")

    local _xdg_data_canon _root_canon
    _xdg_data_canon="$(readlink -f "${XDG_DATA_HOME}" 2> /dev/null || printf '%s' "${XDG_DATA_HOME}")"
    _root_canon="$(readlink -f /root 2> /dev/null || printf '%s' /root)"

    _BLOCKED_PREFIXES=()
    local _home_root
    for _home_root in "${_HOME_ROOTS[@]}"; do
        _BLOCKED_PREFIXES+=(
            # SSH / GPG / cloud keys
            "${_home_root}/.ssh"
            "${_home_root}/.gnupg"
            "${_home_root}/.aws"
            "${_home_root}/.kube"
            "${_home_root}/.docker"
            # Package-manager credentials
            "${_home_root}/.netrc"
            "${_home_root}/.pypirc"
            "${_home_root}/.rattler"
            "${_home_root}/.yarnrc"
            "${_home_root}/.yarnrc.yml"
            "${_home_root}/.yarn"
            # Password managers
            "${_home_root}/.password-store"   # pass / gopass encrypted secret store
            "${_home_root}/.config/1Password" # 1Password CLI session/config
            "${_home_root}/.config/op"        # 1Password CLI (alternate path)
            # GitHub CLI tokens
            "${_home_root}/.config/gh"
        )
    done

    # uv per-index credentials under XDG_DATA_HOME (logical + canonical).
    _BLOCKED_PREFIXES+=("${XDG_DATA_HOME}/uv/credentials")
    [[ "${_xdg_data_canon}" != "${XDG_DATA_HOME}" ]] &&
        _BLOCKED_PREFIXES+=("${_xdg_data_canon}/uv/credentials")

    # System paths.
    _BLOCKED_PREFIXES+=(
        "/root"
        "/etc/shadow"
        "/etc/sudoers"
        "/etc/sudoers.d"
    )
    [[ "${_root_canon}" != "/root" ]] && _BLOCKED_PREFIXES+=("${_root_canon}")

    # Return success explicitly: the trailing `[[ ... ]] && ...` above yields a
    # non-zero status when its condition is false, which under the callers'
    # `set -e` would otherwise abort the whole run.
    return 0
}

# _check_dir_safe PATH CONTEXT
#   Convenience wrapper around _check_path_safe for directory paths that may
#   or may not exist yet (e.g. tool-home dirs created later by ensure_host_dirs).
#
#   If PATH exists on the host, it is canonicalized via readlink -f first so
#   that symlinks in the path are resolved before the safety check.  If it does
#   not yet exist, the raw value is checked as-is; this still catches obviously
#   dangerous literals like $HOME, /root, or ~/.ssh even before the directory
#   is created.
#
#   PATH    : absolute path to check.
#   CONTEXT : short label for error messages (e.g. "PIXI_HOME", "CLAUDE_HOME").
_check_dir_safe() {
    local path="$1"
    local context="$2"
    local canon
    if [[ -e "${path}" ]]; then
        canon="$(readlink -f "${path}" 2> /dev/null || echo "${path}")"
    else
        canon="${path}"
    fi
    _check_path_safe "${canon}" "${context}"
}

# validate_extra_path RAW_PATH MODE
#   Validate a user-supplied path (from --ro-path or --rw-path) before
#   mounting it into the sandbox.
#
#   RAW_PATH : path string supplied by the user; may contain a leading ~/
#              or be relative — resolved via tilde expansion + readlink -f.
#   MODE     : "ro" or "rw" — used only in error messages.
#
#   On success: echoes the canonical resolved path to stdout.
#   On failure: prints an error to stderr and exits 1.
#
#   Steps:
#     1. Expand leading ~/ then resolve to canonical path via readlink -f.
#     2. Verify the path exists on the host.
#     3. Delegate safety checks to _check_path_safe.
validate_extra_path() {
    local raw_path="$1"
    local mode="$2"

    # Expand a leading ~/ or ~user/ to a real path (readlink -f won't do this
    # for us).  Reject an unresolvable ~user rather than corrupting the path.
    local expanded_path
    if ! expanded_path="$(_expand_leading_tilde "${raw_path}")"; then
        echo "Error: --${mode}-path '${raw_path}': cannot resolve '~user' home directory." >&2
        exit 1
    fi

    # Resolve to canonical path (follows symlinks, removes . and ..).
    local canon
    canon="$(readlink -f "${expanded_path}" 2> /dev/null || true)"

    # ── Existence check ──────────────────────────────────────────
    if [[ -z "${canon}" ]] || ! [[ -e "${canon}" ]]; then
        echo "Error: --${mode}-path '${raw_path}': path does not exist." >&2
        exit 1
    fi

    # ── Safety check ─────────────────────────────────────────────
    _check_path_safe "${canon}" "--${mode}-path"

    # All checks passed — return the canonical path.
    echo "${canon}"
}

# ── Extra user path mounts ───────────────────────────────────────

# build_extra_path_mounts
#   Mount all paths accumulated in EXTRA_RO_PATHS and EXTRA_RW_PATHS.
#   Each path is validated by validate_extra_path (which runs _check_path_safe)
#   before mounting.
#
#   Binds are emitted ANCESTORS-FIRST across both modes: bwrap applies binds in
#   order and the last one covering a mount point wins, so a path nested under
#   another is emitted after its parent and correctly overrides it.  This lets
#       --rw-path parent --ro-path parent/child
#   protect a specific subdirectory (writable parent, read-only child), and
#   equally the reverse (read-only tree with one writable subdir).
#
#   User paths are emitted DIRECTLY (not through the _MOUNTED_PREFIXES dedup
#   used for automatic tool/system mounts): that dedup would skip a child
#   already "covered" by a parent bind and defeat the nesting — and would also
#   block protecting a subdirectory of the already-bound working directory.
#
#   Must be called AFTER the automatic mount steps (workdir, tool, system,
#   home) so an explicit --ro-path/--rw-path can override them, and AFTER
#   build_home_tmpfs (which creates the $HOME tmpfs that intermediate --dir
#   entries populate).
build_extra_path_mounts() {
    # Nothing to do if the user passed no extra paths.
    [[ ${#EXTRA_RO_PATHS[@]} -eq 0 && ${#EXTRA_RW_PATHS[@]} -eq 0 ]] && return 0

    local _raw_path _canon _mode
    local -A _mode_of=()

    # Validate everything up front (canonicalizing each path) via a command
    # substitution.  The explicit `|| exit` matters: validate_extra_path's own
    # `exit 1` only terminates the subshell, so we must propagate it rather than
    # continue with an empty canonical path.
    for _raw_path in "${EXTRA_RO_PATHS[@]+"${EXTRA_RO_PATHS[@]}"}"; do
        _canon="$(validate_extra_path "${_raw_path}" "ro")" || exit 1
        _mode_of["${_canon}"]="ro"
    done
    for _raw_path in "${EXTRA_RW_PATHS[@]+"${EXTRA_RW_PATHS[@]}"}"; do
        _canon="$(validate_extra_path "${_raw_path}" "rw")" || exit 1
        # A path given as BOTH --ro-path and --rw-path is contradictory.
        if [[ "${_mode_of["${_canon}"]:-}" == "ro" ]]; then
            echo "Error: '${_canon}' was given as both --ro-path and --rw-path." >&2
            echo "       A path cannot be mounted read-only and read-write at once." >&2
            exit 1
        fi
        _mode_of["${_canon}"]="rw"
    done

    # Order the paths ancestors-first.  A plain LC_ALL=C sort suffices because
    # an ancestor path is a byte prefix of its descendants, so it sorts before
    # them.  (Limitation: a path containing a newline is not ordered reliably —
    # sort is line-based; such paths are pathological and out of scope.)
    local -a _all_canon=() _sorted=()
    for _canon in "${!_mode_of[@]}"; do
        _all_canon+=("${_canon}")
    done
    mapfile -t _sorted < <(printf '%s\n' "${_all_canon[@]}" | LC_ALL=C sort)

    # Collect the destinations of every bind already emitted (workdir, tool,
    # system, home, and — as we go — earlier extra paths).  A path whose
    # ancestor is already bind-mounted needs no intermediate --dir entries: the
    # ancestor's real host tree already contains it, and emitting a --dir on top
    # of an existing bind would clobber that bind.  _bwrap_flag_arity keeps the
    # walk aligned across variable-arity flags.
    local -A _bound_dests=()
    local _bi=0 _bflag _barity
    while [[ ${_bi} -lt ${#BWRAP_ARGS[@]} ]]; do
        _bflag="${BWRAP_ARGS[${_bi}]}"
        _barity="$(_bwrap_flag_arity "${_bflag}")"
        case "${_bflag}" in
            --bind | --bind-try | --ro-bind | --ro-bind-try | --dev-bind | --dev-bind-try)
                # Two-arg bind: SRC at _bi+1, DEST (the mount point) at _bi+2.
                _bound_dests["${BWRAP_ARGS[$((_bi + 2))]}"]=1
                ;;
        esac
        _bi=$((_bi + 1 + _barity))
    done

    local _anc
    for _canon in "${_sorted[@]}"; do
        _mode="${_mode_of["${_canon}"]}"

        # Does any already-bound ancestor make this path reachable already?
        local _has_bound_ancestor=0
        _anc="${_canon%/*}"
        [[ -z "${_anc}" ]] && _anc="/"
        while :; do
            if [[ -n "${_bound_dests["${_anc}"]:-}" ]]; then
                _has_bound_ancestor=1
                break
            fi
            [[ "${_anc}" == "/" ]] && break
            _anc="${_anc%/*}"
            [[ -z "${_anc}" ]] && _anc="/"
        done

        # Pre-create intermediate --dir entries only when no bound ancestor
        # already provides the path (otherwise the --dir would clobber it).
        # _emit_home_intermediate_dirs is a no-op for paths outside $HOME.
        if [[ ${_has_bound_ancestor} -eq 0 ]]; then
            if [[ -d "${_canon}" && "${_mode}" == "rw" ]]; then
                # RW dir: include the target in the chain (the --bind lands on
                # top of that --dir).
                _emit_home_intermediate_dirs "${_canon}" inclusive
            elif [[ -d "${_canon}" ]]; then
                # RO dir: the --ro-bind creates the mount point, so only its
                # ancestors need pre-creating.
                _emit_home_intermediate_dirs "${_canon}"
            else
                # File (either mode): pre-create the parent directory chain.
                _emit_home_intermediate_dirs "${_canon%/*}" inclusive
            fi
        fi

        if [[ "${_mode}" == "ro" ]]; then
            BWRAP_ARGS+=(--ro-bind "${_canon}" "${_canon}")
        else
            BWRAP_ARGS+=(--bind "${_canon}" "${_canon}")
        fi
        # Record this bind so a nested child skips its intermediate --dir.
        _bound_dests["${_canon}"]=1
    done
}

# ── Path resolution ──────────────────────────────────────────────

resolve_common_paths() {
    _HOME="${HOME}"
    # Canonical home: home may be reached through a symlink (e.g. /home ->
    # /nfs/home on NFS/automount hosts).  Candidate paths are canonicalized
    # with readlink -f before the safety checks, so the blocked-prefix list
    # must be expressed in the canonical home too — otherwise a canonicalized
    # candidate slips past a prefix that was built from the logical home.
    _HOME_CANON="$(readlink -f "${HOME}" 2> /dev/null || printf '%s' "${HOME}")"

    # Physical (symlink-resolved) working directory.  Using the physical path
    # keeps PWD and the working-directory bind consistent with the canonical
    # candidate checks below and with what actually exists inside the sandbox.
    _PWD="$(pwd -P 2> /dev/null || printf '%s' "${PWD}")"

    # Guarded username: $USER can be unset under `set -u` (cron/CI); fall back
    # to `id -un` so USER/LOGNAME in the sandbox are always populated.
    _USER="${USER:-$(id -un)}"

    # XDG defaults
    XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-${_HOME}/.config}"
    XDG_DATA_HOME="${XDG_DATA_HOME:-${_HOME}/.local/share}"
    XDG_CACHE_HOME="${XDG_CACHE_HOME:-${_HOME}/.cache}"

    # Pixi paths
    PIXI_HOME_DIR="${PIXI_HOME:-${_HOME}/.pixi}"

    # ccache paths
    # ccache cache: $CCACHE_DIR, else ~/.ccache if it exists (legacy), else $XDG_CACHE_HOME/ccache
    if [[ -n "${CCACHE_DIR:-}" ]]; then
        CCACHE_CACHE_DIR="${CCACHE_DIR}"
    elif [[ -d "${_HOME}/.ccache" ]]; then
        CCACHE_CACHE_DIR="${_HOME}/.ccache"
    else
        CCACHE_CACHE_DIR="${XDG_CACHE_HOME}/ccache"
    fi
    # ccache config: if legacy ~/.ccache dir exists, config is inside it;
    # otherwise $XDG_CONFIG_HOME/ccache
    if [[ -d "${_HOME}/.ccache" ]]; then
        CCACHE_CONFIG_DIR="${_HOME}/.ccache"
    else
        CCACHE_CONFIG_DIR="${XDG_CONFIG_HOME}/ccache"
    fi

    # npm paths
    NPM_CACHE_DIR="${NPM_CONFIG_CACHE:-${_HOME}/.npm}"

    # Precompute the blocked-prefix / home-root lists (needs XDG_DATA_HOME).
    _build_blocked_prefixes

    # ── Safety checks on all user-controllable path roots ────────
    # These variables are set from env vars (XDG_*, PIXI_HOME, CCACHE_DIR,
    # NPM_CONFIG_CACHE) and control where entire directory trees are mounted
    # into the sandbox.  Validate each root once here so that every mount
    # derived from it is implicitly covered — no per-mount check needed for
    # sub-paths.  Paths that do not yet exist are checked against the blocked
    # list anyway (catches e.g. PIXI_HOME=~/.ssh before .pixi is created).
    _check_dir_safe "${XDG_CONFIG_HOME}"  "XDG_CONFIG_HOME"
    _check_dir_safe "${XDG_DATA_HOME}"    "XDG_DATA_HOME"
    _check_dir_safe "${XDG_CACHE_HOME}"   "XDG_CACHE_HOME"
    _check_dir_safe "${PIXI_HOME_DIR}"    "PIXI_HOME"
    _check_dir_safe "${CCACHE_CACHE_DIR}" "CCACHE_DIR (cache)"
    _check_dir_safe "${CCACHE_CONFIG_DIR}" "CCACHE_DIR (config)"
    _check_dir_safe "${NPM_CACHE_DIR}"    "NPM_CONFIG_CACHE"
}

# ── Sandbox PATH construction ────────────────────────────────────

init_sandbox_path() {
    SANDBOX_PATH="/usr/lib64/ccache:/usr/local/sbin:/usr/local/bin:/usr/bin"
    SANDBOX_PATH="${SANDBOX_PATH}:${PIXI_HOME_DIR}/bin"
    SANDBOX_PATH="${SANDBOX_PATH}:${_HOME}/bin"
    if [[ -d /nsls2/software/bin ]]; then
        SANDBOX_PATH="${SANDBOX_PATH}:/nsls2/software/bin"
    fi
    # Additional bin directories discovered during dynamic tool mounts are
    # appended to SANDBOX_PATH by finalize_sandbox_path.
}

# Append dynamically-discovered bin directories to SANDBOX_PATH.
# Deduplicates: the same dir can be recorded more than once (e.g. an npm bin
# dir added both as a tool's on-PATH dir and as the npm prefix's bin/), and a
# dir already present in the base SANDBOX_PATH need not be appended again.
finalize_sandbox_path() {
    local _extra_dir
    declare -A _path_seen=()
    # Seed with the base PATH entries so we don't re-append them.
    local _base_dir
    local -a _base_dirs=()
    IFS=':' read -ra _base_dirs <<< "${SANDBOX_PATH}"
    for _base_dir in "${_base_dirs[@]}"; do
        [[ -n "${_base_dir}" ]] && _path_seen["${_base_dir}"]=1
    done
    for _extra_dir in "${_EXTRA_PATH_DIRS[@]+"${_EXTRA_PATH_DIRS[@]}"}"; do
        [[ -z "${_extra_dir}" ]] && continue
        [[ -n "${_path_seen["${_extra_dir}"]:-}" ]] && continue
        _path_seen["${_extra_dir}"]=1
        SANDBOX_PATH="${SANDBOX_PATH}:${_extra_dir}"
    done
}

# ═══════════════════════════════════════════════════════════════════
# Shared sandbox construction functions
# ═══════════════════════════════════════════════════════════════════
# Each build_* function appends to the global BWRAP_ARGS array.
# They must be called in the correct order to produce valid bwrap
# arguments — see the tool wrapper's main() for the canonical sequence.

# ── Namespace isolation + base system (read-only) ────────────────
build_base_sandbox() {
    # --unshare-pid: Isolate the PID namespace so the sandbox cannot see
    #   or inspect host processes via /proc (prevents reading environ,
    #   cmdlines, and discovering services like ssh-agent).
    # --new-session: Calls setsid(2) — detaches the controlling terminal
    #   and creates a new session.  Originally added to block TIOCSTI
    #   ioctl keystroke injection into the parent terminal.  On kernels
    #   >= 5.14 TIOCSTI requires CAP_SYS_ADMIN (which bwrap drops), so
    #   the kernel guard subsumes the TIOCSTI side of this protection
    #   AND we want to omit --new-session so SIGWINCH (terminal resize)
    #   propagates correctly from tmux/screen to the sandboxed TUI.
    #
    #   Residual exposure when --new-session is omitted:
    #     - The sandbox keeps the controlling tty.  A direct
    #       open("/dev/tty") is mitigated in build_proc_dev_tmp by
    #       binding /dev/null over /dev/tty, but a malicious child can
    #       STILL reach the controlling tty via the inherited pty fds
    #       (fd 0/1/2), reachable as /proc/self/fd/0.  Closing the
    #       /proc/self/fd reopen path would require --unshare-user or
    #       hidepid=2 on /proc, neither of which we currently use.
    #     - Via that reopened fd, an attacker CAN:
    #         * write arbitrary bytes (display spoofing, escape
    #           sequences, fake TUI content)
    #         * call tcsetattr() to manipulate termios (disable echo)
    #     - Via that reopened fd, an attacker CANNOT
    #         * inject keystrokes via TIOCSTI — blocked by the 5.14
    #           kernel cap guard (returns EIO)
    #         * steal the foreground process group via tcsetpgrp —
    #           fails with ENOTTY (we have no controlling tty of our
    #           own, only an open fd to someone else's)
    #         * reliably read keystrokes — the TUI parent consumes
    #           them first, and the kernel gates this for non-CTTY fds
    #     - Escape-sequence-based attacks via stdout (OSC 52 clipboard
    #       hijack, terminal-response injection on legacy emulators)
    #       are NOT mitigated by --new-session either — stdout is
    #       already a direct path to the user's terminal.  These are
    #       the TUI's responsibility (filter tool output) and out of
    #       scope here.
    #
    #   Users can force --new-session via the wrapper's --new-session
    #   flag (which sets FORCE_NEW_SESSION=1), e.g. for non-interactive
    #   runs where SIGWINCH propagation is unimportant.  Note that
    #   --new-session does NOT close the /proc/self/fd reopen path — it
    #   only detaches the controlling terminal, not already-open fds
    #   held by other processes in the sandbox.
    # --die-with-parent: Kill the sandbox if the parent process exits, to
    #   prevent orphaned sandbox processes.
    # Network is shared so the tool can reach LLM APIs and GitHub OAuth.
    BWRAP_ARGS+=(
        --unshare-pid
        --die-with-parent
    )
    if [[ "${FORCE_NEW_SESSION}" -eq 1 ]] || [[ "${KERNEL_HAS_TIOCSTI_CAP_GUARD}" -eq 0 ]]; then
        BWRAP_ARGS+=(--new-session)
    fi

    # Base system (read-only)
    BWRAP_ARGS+=(
        --ro-bind /usr /usr
    )
    # /bin, /sbin, /lib, and /lib64 may be real directories (Debian-family)
    # or symlinks into /usr (Fedora/Arch).  Bind the real dir, or recreate
    # the symlink so tools expecting e.g. /bin/bash still work.
    local _dir
    for _dir in /bin /sbin /lib /lib64; do
        if [[ -L "${_dir}" ]]; then
            BWRAP_ARGS+=(--symlink "$(readlink "${_dir}")" "${_dir}")
        elif [[ -d "${_dir}" ]]; then
            BWRAP_ARGS+=(--ro-bind "${_dir}" "${_dir}")
        fi
    done
}

# ── Mask dangerous binaries ───────────────────────────────────────
# Bind /dev/null over security-sensitive binaries so attempts to
# execute them fail rather than silently working.
#
# This requires bwrap >= 0.6.3 which supports binding over paths inside
# an existing read-only bind mount.  On older versions, we skip masking
# entirely (the binaries remain accessible inside the sandbox).
#
# Categories:
#   SSH           – lateral movement via remote shell / file transfer
#   Network       – arbitrary TCP/UDP connections, reverse shells
#   Kerberos      – ticket-based authentication to network services
#   Keyring       – kernel keyring manipulation
#   Priv-escalation – sudo/su/pkexec
#   Namespace     – sandbox escape via nsenter/unshare/chroot
build_binary_masks() {
    [[ "${HAS_BIND_OVER_RO}" -eq 1 ]] || return 0

    local _MASKED_BINS=(
        # SSH
        ssh scp sftp ssh-agent ssh-add ssh-keygen ssh-keyscan
        # Network
        # NOTE: socat is deliberately NOT masked — Claude Code's built-in
        # bwrap sandbox uses socat internally, and masking it breaks that
        # functionality inside our outer sandbox.
        telnet nc ncat netcat rsync rsh rlogin rexec
        # Kerberos
        kinit klist kdestroy kswitch
        # Keyring
        keyctl
        # Privilege escalation
        sudo su pkexec
        # Namespace / sandbox escape
        nsenter unshare chroot
    )
    # Canonicalize + dedupe the search prefixes once.  On merged-/usr systems
    # /bin, /sbin, /usr/bin, /usr/sbin resolve to the same directory; collapsing
    # them here avoids re-checking (and re-resolving) the same candidate under
    # several aliases.  Search prefixes cover RHEL, Debian, and Arch layouts.
    declare -A _prefix_seen=()
    local -a _canon_prefixes=()
    local _p _pc
    for _p in /usr/bin /usr/sbin /usr/lib/openssh /usr/libexec/openssh /bin /sbin; do
        [[ -d "${_p}" ]] || continue
        _pc="$(readlink -f "${_p}" 2> /dev/null || printf '%s' "${_p}")"
        [[ -n "${_prefix_seen["${_pc}"]:-}" ]] && continue
        _prefix_seen["${_pc}"]=1
        _canon_prefixes+=("${_pc}")
    done
    [[ ${#_canon_prefixes[@]} -gt 0 ]] || return 0

    # Collect every existing candidate binary across the unique prefixes.
    # -e follows symlinks: true only if the full chain resolves to a real file,
    # so dangling alternatives entries are skipped (correct — nothing to mask).
    local -a _candidates=()
    local _bin _candidate
    for _bin in "${_MASKED_BINS[@]}"; do
        for _pc in "${_canon_prefixes[@]}"; do
            _candidate="${_pc}/${_bin}"
            [[ -e "${_candidate}" ]] && _candidates+=("${_candidate}")
        done
    done
    [[ ${#_candidates[@]} -gt 0 ]] || return 0

    # On RHEL/Debian the binary is often a symlink:
    #   /usr/bin/nc -> /etc/alternatives/nc -> /usr/bin/ncat
    # bwrap processes --ro-bind arguments in order; at the point the bind is
    # applied /etc/alternatives is not yet mounted, so bwrap cannot resolve the
    # intermediate symlink ("Can't create file at /usr/bin/nc").  Resolve every
    # candidate to its canonical, symlink-free path (always reachable under /usr
    # once --ro-bind /usr /usr is applied) and mask *that*.  A single readlink
    # -f fork resolves all candidates at once (was one realpath fork each).
    declare -A _masked_real_seen=()
    local _real
    while IFS= read -r _real; do
        [[ -n "${_real}" ]] || continue
        [[ -n "${_masked_real_seen["${_real}"]:-}" ]] && continue
        _masked_real_seen["${_real}"]=1
        BWRAP_ARGS+=(--ro-bind /dev/null "${_real}")
    done < <(readlink -f "${_candidates[@]}")
}

build_proc_dev_tmp() {
    BWRAP_ARGS+=(
        --proc /proc
        --dev /dev
        --tmpfs /tmp
    )

    # Mask /dev/tty unless --new-session is active.
    #
    # With --new-session bwrap detaches the controlling terminal, so
    # open("/dev/tty") returns ENXIO inside the sandbox — there is no
    # tty to find.  Without --new-session (the default on kernels with
    # the TIOCSTI cap-guard, where we drop --new-session to let SIGWINCH
    # through), the sandboxed process inherits the controlling terminal
    # and can open /dev/tty as a direct, un-redirectable, un-loggable
    # channel to the user's terminal.  Binding /dev/null over /dev/tty
    # blocks the naïve open("/dev/tty") path.
    #
    # Scope of this mitigation: closes the obvious API path used by
    # legitimate tools (sudo, ssh-askpass, gpg-agent) and by naïve
    # malicious dependencies.  Does NOT close the procfs-fd-reopen
    # bypass — see the long comment in build_base_sandbox for the
    # threat-model details.  Closing that bypass needs a separate user
    # namespace or hidepid=2 on /proc.
    #
    # Programs typically use isatty(0/1/2) — which still works on the
    # inherited stdio fds — to detect interactivity, so masking
    # /dev/tty rarely breaks tools that aren't actively trying to
    # bypass stdio.
    if [[ "${FORCE_NEW_SESSION}" -ne 1 ]] && [[ "${KERNEL_HAS_TIOCSTI_CAP_GUARD}" -eq 1 ]]; then
        BWRAP_ARGS+=(--bind /dev/null /dev/tty)
    fi
}

# ── Selective /sys (read-only) ───────────────────────────────────
# Expose only CPU and NUMA-node topology so tools can size thread
# pools and place work sensibly (nproc/hwloc/OpenMP/BLAS, NUMA-aware
# allocators).  Everything else under /sys is deliberately omitted.
#
# Scope and rationale:
#   /sys/devices/system/cpu   — CPU topology, core/thread counts,
#                               online mask, cache layout.
#   /sys/devices/system/node  — NUMA node layout (cpulist, meminfo,
#                               distance); consulted by hwloc and
#                               NUMA-aware threading/BLAS libraries.
#
# Mounted read-only (--ro-bind), never --dev-bind: sysfs stays
# non-writable so the classic write vectors (changing hardware state,
# uevent helpers, cgroup/security nodes) are out of reach.  We do NOT
# bind all of /sys — that would pull in /sys/kernel, /sys/fs/cgroup,
# /sys/class, /sys/firmware, /sys/power, etc.  The only residual
# exposure from these two subtrees is host hardware fingerprinting
# (an info leak, largely redundant with /proc/cpuinfo which is already
# visible via --proc), not privilege escalation.
#
# --ro-bind-try so the sandbox still works on hosts/kernels where a
# node is absent (e.g. non-NUMA kernels lacking /sys/devices/system/node).
build_sys_mounts() {
    BWRAP_ARGS+=(
        --ro-bind-try /sys/devices/system/cpu /sys/devices/system/cpu
        --ro-bind-try /sys/devices/system/node /sys/devices/system/node
    )
}

# ── Selective /etc (read-only) ───────────────────────────────────
# Only expose what is needed for DNS, TLS, user identity, and NSS.
build_etc_mounts() {
    BWRAP_ARGS+=(
        --ro-bind-try /etc/resolv.conf /etc/resolv.conf
        --ro-bind-try /etc/hosts /etc/hosts
        --ro-bind-try /etc/nsswitch.conf /etc/nsswitch.conf
        --ro-bind /etc/passwd /etc/passwd
        --ro-bind /etc/group /etc/group
        --ro-bind-try /etc/ssl /etc/ssl
        --ro-bind-try /etc/pki /etc/pki
        --ro-bind-try /etc/crypto-policies /etc/crypto-policies
        --ro-bind-try /etc/ca-certificates /etc/ca-certificates
        --ro-bind-try /etc/alternatives /etc/alternatives
        --ro-bind-try /etc/ld.so.cache /etc/ld.so.cache
        --ro-bind-try /etc/ld.so.conf /etc/ld.so.conf
        --ro-bind-try /etc/ld.so.conf.d /etc/ld.so.conf.d
        --ro-bind-try /etc/localtime /etc/localtime
        --ro-bind-try /etc/gitconfig /etc/gitconfig
    )
}

# ── Home directory (empty tmpfs, then selective mounts) ──────────
build_home_tmpfs() {
    BWRAP_ARGS+=(
        --tmpfs "${_HOME}"
    )

    # Create intermediate directories that are needed as mount points
    # inside the tmpfs $HOME.
    BWRAP_ARGS+=(
        --dir "${_HOME}/.config"
        --dir "${_HOME}/.local"
        --dir "${_HOME}/.local/share"
        --dir "${_HOME}/.cache"
        --dir "${_HOME}/bin"
    )
}

# ── Working directory (read-write) ────────────────────────────────
# If we are inside a git repo, bind the repo root so the tool can
# find .git and identify the project (sessions are keyed to the repo).
# Otherwise fall back to binding just $PWD.
# Sets globals: _BIND_DIR, _GIT_ROOT
build_workdir_mount() {
    # _PWD is the physical (pwd -P) working directory; git rev-parse
    # --show-toplevel likewise returns a physical path.
    _BIND_DIR="${_PWD}"
    _GIT_ROOT="$(git -C "${_PWD}" rev-parse --show-toplevel 2> /dev/null || true)"
    if [[ -n "${_GIT_ROOT}" ]]; then
        _BIND_DIR="${_GIT_ROOT}"
    fi

    # Canonicalize before the safety check.  Although pwd -P and git rev-parse
    # already return physical paths, resolving once more with readlink -f
    # guarantees a symlinked working directory cannot smuggle a blocked target
    # (e.g. a cwd symlinked into ~/.ssh) past _check_path_safe, which compares
    # the canonical candidate against the blocked-prefix list.
    _BIND_DIR="$(readlink -f "${_BIND_DIR}" 2> /dev/null || printf '%s' "${_BIND_DIR}")"

    # Guard: reject dangerous working / git-root directories via the same
    # rules applied to --ro-path / --rw-path.  This catches $HOME itself,
    # ancestors of $HOME (/home, /), /root, ~/.ssh, and all other blocked
    # prefixes.
    _check_path_safe "${_BIND_DIR}" "working directory"

    # If the bind dir is under HOME, create intermediate directories in the
    # tmpfs so the bind mount point is reachable.  _BIND_DIR is itself the
    # bind mount point, so only its ancestors are pre-created.
    _emit_home_intermediate_dirs "${_BIND_DIR}"
    BWRAP_ARGS+=(
        --bind "${_BIND_DIR}" "${_BIND_DIR}"
    )

    # Register the workdir in _MOUNTED_PREFIXES so any later tool mounts that
    # resolve from inside the repo (e.g. repo-local node_modules/.bin or
    # .pixi/envs/*/bin on PATH) do not emit an --ro-bind on top of this RW bind.
    # Later mounts win; an --ro-bind overlay would make that subtree read-only,
    # causing npm install / pixi install to fail with EROFS.
    #
    # This function is called BEFORE build_dynamic_tool_mounts in every wrapper
    # (verified in bin/bw{claude,codex,copilot,opencode}:main), so the dedup
    # logic in resolve_and_mount_tool → _mount_ro_dir_if_needed will correctly
    # skip any dir already covered by this bind.
    _MOUNTED_PREFIXES["${_BIND_DIR}"]=1
}

# ── Git config (read-only) ──────────────────────────────────────
build_git_mounts() {
    # Resolve symlinks so we bind the real file (readlink -f is a no-op on
    # regular files).  Check the resolved target before emitting the bind:
    # ~/.gitconfig could be a symlink pointing anywhere on the filesystem.
    if [[ -f "${_HOME}/.gitconfig" ]]; then
        local _gitconfig_real
        _gitconfig_real="$(readlink -f "${_HOME}/.gitconfig")"
        _check_path_safe "${_gitconfig_real}" "\$HOME/.gitconfig (resolved)"
        BWRAP_ARGS+=(--ro-bind "${_gitconfig_real}" "${_HOME}/.gitconfig")
    fi
    if [[ -d "${XDG_CONFIG_HOME}/git" ]]; then
        # XDG_CONFIG_HOME is already validated by resolve_common_paths;
        # no additional check needed here.
        BWRAP_ARGS+=(--ro-bind "${XDG_CONFIG_HOME}/git" "${XDG_CONFIG_HOME}/git")
    fi

    # Git include files (read-only).  Bind each file's canonical target
    # (GIT_INCLUDE_TARGETS, symlink-chased by parse_git_includes) at its
    # LOGICAL path (GIT_INCLUDE_PATHS) — the path written in the config is
    # what git opens, and the host's symlink chain does not exist inside the
    # tmpfs $HOME.  Same source-at-logical-destination treatment as
    # ~/.gitconfig above.  Safety is checked on the canonical target — that
    # is the data actually exposed; a git config could contain
    # path = ~/.ssh/id_rsa or similar.
    declare -A _GIT_INC_DIRS_SEEN=()
    local _inc_i inc_path inc_target local_parent
    for ((_inc_i = 0; _inc_i < ${#GIT_INCLUDE_PATHS[@]}; _inc_i++)); do
        inc_path="${GIT_INCLUDE_PATHS[${_inc_i}]}"
        inc_target="${GIT_INCLUDE_TARGETS[${_inc_i}]}"
        _check_path_safe "${inc_target}" "git include path"
        # Ensure parent directory exists as a mount point (deduplicated)
        local_parent="${inc_path%/*}"
        if [[ -z "${_GIT_INC_DIRS_SEEN["${local_parent}"]:-}" ]]; then
            _GIT_INC_DIRS_SEEN["${local_parent}"]=1
            BWRAP_ARGS+=(--dir "${local_parent}")
        fi
        BWRAP_ARGS+=(--ro-bind-try "${inc_target}" "${inc_path}")
    done
}

# ── Pixi cache (read-write) + config (read-only) ────────────────
build_pixi_mounts() {
    if [[ -d "${PIXI_HOME_DIR}" ]]; then
        BWRAP_ARGS+=(--bind "${PIXI_HOME_DIR}" "${PIXI_HOME_DIR}")
    fi

    # Pixi checks multiple config locations; bind any that exist.
    if [[ -f "${XDG_CONFIG_HOME}/pixi/config.toml" ]]; then
        BWRAP_ARGS+=(
            --dir "${XDG_CONFIG_HOME}/pixi"
            --ro-bind "${XDG_CONFIG_HOME}/pixi/config.toml" "${XDG_CONFIG_HOME}/pixi/config.toml"
        )
    fi
    if [[ -f "${_HOME}/.pixi/config.toml" ]]; then
        # Already available via the pixi overlay, but if the overlay is not
        # present (dir doesn't exist), bind it explicitly.
        if [[ ! -d "${PIXI_HOME_DIR}" ]]; then
            BWRAP_ARGS+=(--ro-bind "${_HOME}/.pixi/config.toml" "${_HOME}/.pixi/config.toml")
        fi
    fi
}

# ── ccache config (read-only) + cache (read-write) ──────────────
build_ccache_mounts() {
    if [[ -d "${CCACHE_CONFIG_DIR}" ]]; then
        BWRAP_ARGS+=(
            --dir "${CCACHE_CONFIG_DIR%/*}"
            --ro-bind "${CCACHE_CONFIG_DIR}" "${CCACHE_CONFIG_DIR}"
        )
    fi

    if [[ -d "${CCACHE_CACHE_DIR}" ]]; then
        BWRAP_ARGS+=(--bind "${CCACHE_CACHE_DIR}" "${CCACHE_CACHE_DIR}")
    fi
}

# ── npm config (read-only) + cache (read-write) ─────────────────
build_npm_mounts() {
    if [[ -f "${_HOME}/.npmrc" ]]; then
        BWRAP_ARGS+=(--ro-bind "${_HOME}/.npmrc" "${_HOME}/.npmrc")
    fi

    if [[ -d "${NPM_CACHE_DIR}" ]]; then
        BWRAP_ARGS+=(--bind "${NPM_CACHE_DIR}" "${NPM_CACHE_DIR}")
    fi
}

# ── User binaries (read-only) ───────────────────────────────────
build_user_bin_mount() {
    if [[ -d "${_HOME}/bin" ]]; then
        BWRAP_ARGS+=(--ro-bind "${_HOME}/bin" "${_HOME}/bin")
    fi
}

# ── NSLS-II software (read-only) ────────────────────────────────
# Only bind if the directory exists on the host system.
build_nsls2_mount() {
    if [[ -d /nsls2/software/bin ]]; then
        BWRAP_ARGS+=(
            --dir /nsls2/software
            --ro-bind /nsls2/software/bin /nsls2/software/bin
        )
    fi
}

# ── Dynamic tool mounts (tool binary, pixi, npm global) ──────────
# Pre-populate _MOUNTED_PREFIXES with every directory tree that is
# already unconditionally mounted above so _mount_ro_dir_if_needed
# skips them without re-mounting.
build_dynamic_tool_mounts() {
    local _preloaded
    for _preloaded in \
            /usr /bin /sbin /lib /lib64 \
            /proc /dev /tmp \
            "${PIXI_HOME_DIR}" \
            "${_HOME}/bin" \
            /nsls2/software/bin; do
        [[ -e "${_preloaded}" ]] && _MOUNTED_PREFIXES["${_preloaded}"]=1
    done

    # Resolve each tool binary dynamically.  resolve_and_mount_tool handles
    # the symlink chain and detects npm-installed binaries automatically,
    # delegating to _mount_npm_global_prefix for those.
    local _tool_bin
    for _tool_bin in \
            "${_TOOL_BIN}" \
            "$(command -v pixi 2> /dev/null || true)"; do
        [[ -n "${_tool_bin}" ]] && resolve_and_mount_tool "${_tool_bin}"
    done

    # npm global prefix: mount even when the tool is not npm-installed so
    # that any globally-installed Node.js tools are available in the sandbox.
    _mount_npm_global_prefix

    finalize_sandbox_path
}

# ── Environment variables ────────────────────────────────────────
# Start from a clean environment and only pass through what we need.
build_env_vars() {
    if [[ "${HAS_CLEARENV}" -eq 1 ]]; then
        BWRAP_ARGS+=(--clearenv)
    else
        # Fallback for bwrap < 0.5.0: manually unset all host env vars.
        # We use compgen -e to list all exported vars and unset each one.
        # Note: we already exec with env -i, but --unsetenv ensures any
        # vars inherited through other means are also cleared.
        #
        # Read line-by-line (not `for x in $(...)`) so names are not
        # word-split on IFS, and skip anything that is not a portable
        # shell identifier — bash exports function definitions under names
        # like `BASH_FUNC_module%%`, which would become invalid --unsetenv
        # arguments.
        #
        # On HPC login nodes the exported-var count can reach the hundreds;
        # each becomes a separate --unsetenv pair, so this path can produce
        # a long bwrap command line.  That is unavoidable here and harmless
        # (well under ARG_MAX); the modern --clearenv path above avoids it.
        local _envvar
        while IFS= read -r _envvar; do
            [[ "${_envvar}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
            BWRAP_ARGS+=(--unsetenv "${_envvar}")
        done < <(compgen -e)
    fi

    # Always set
    BWRAP_ARGS+=(
        --setenv HOME "${_HOME}"
        --setenv USER "${_USER}"
        --setenv LOGNAME "${_USER}"
        --setenv SHELL "${SANDBOX_SHELL}"
        --setenv PATH "${SANDBOX_PATH}"
        --setenv PWD "${_PWD}"
        --setenv TERM "${TERM:-xterm-256color}"
    )

    # Terminal
    pass_through_if_set COLORTERM
    pass_through_if_set TERM_PROGRAM

    # Locale
    pass_through_if_set LANG
    pass_through_if_set LC_ALL
    pass_through_if_set LC_CTYPE
    pass_through_if_set LC_MESSAGES
    pass_through_if_set LC_COLLATE
    pass_through_if_set LC_NUMERIC
    pass_through_if_set LC_TIME
    pass_through_if_set LC_MONETARY

    # XDG (only if explicitly set by user)
    pass_through_if_set XDG_CONFIG_HOME
    pass_through_if_set XDG_DATA_HOME
    pass_through_if_set XDG_CACHE_HOME

    # Tool-specific
    pass_through_if_set CCACHE_DIR
    pass_through_if_set PIXI_HOME
    pass_through_if_set NPM_CONFIG_CACHE

    # Editor
    pass_through_if_set EDITOR
    pass_through_if_set VISUAL

    # Proxy
    pass_through_if_set HTTP_PROXY
    pass_through_if_set HTTPS_PROXY
    pass_through_if_set NO_PROXY
    pass_through_if_set http_proxy
    pass_through_if_set https_proxy
    pass_through_if_set no_proxy

    # Git identity
    pass_through_if_set GIT_AUTHOR_NAME
    pass_through_if_set GIT_AUTHOR_EMAIL
    pass_through_if_set GIT_COMMITTER_NAME
    pass_through_if_set GIT_COMMITTER_EMAIL
}

# ═══════════════════════════════════════════════════════════════════
# Shared launch functions
# ═══════════════════════════════════════════════════════════════════

# Resolve the `env` binary to an absolute path, immune to PATH shadowing.
#
# env is the very first program in the exec chain used by launch_sandbox;
# if it is shadowed (e.g., by a user script earlier on PATH named "env"),
# nothing downstream — bwrap, the tool itself — gets a chance to run
# correctly.  Users almost never have a legitimate reason to provide a
# local override of `env`, so we prefer the canonical /usr/bin/env.
#
# Resolution order:
#   1. /usr/bin/env if it exists and is executable (FHS-mandated location,
#      present on every Linux distro this script targets).
#   2. Fallback to `command -v env` for exotic systems (NixOS, etc.).
#      Note: this fallback IS susceptible to PATH shadowing — but if the
#      canonical location is absent, we have no better option.
#
# Echoes the resolved path to stdout.  Exits with an error if neither
# strategy finds an executable env.
resolve_env_bin() {
    if [[ -x /usr/bin/env ]]; then
        echo /usr/bin/env
        return 0
    fi
    local _env_bin
    _env_bin="$(command -v env 2> /dev/null || true)"
    if [[ -n "${_env_bin}" ]] && [[ -x "${_env_bin}" ]]; then
        echo "${_env_bin}"
        return 0
    fi
    echo "Error: cannot locate the 'env' binary (/usr/bin/env missing and no env on PATH)." >&2
    exit 1
}

# _bwrap_flag_arity FLAG
#   Echo the number of value arguments that bwrap flag FLAG consumes (0, 1,
#   or 2).  Used by print_dry_run to group flags with their values WITHOUT
#   guessing from the value's leading characters — a path value that happens
#   to start with "--" (e.g. a user-supplied --ro-path) must not be mistaken
#   for a new flag.  Only the flags this library actually emits are listed;
#   the default of 1 is a safe fallback for any single-value flag.
_bwrap_flag_arity() {
    case "$1" in
        --unshare-* | --share-net | --die-with-parent | --new-session | \
            --clearenv | --as-pid-1)
            echo 0
            ;;
        --ro-bind | --ro-bind-try | --bind | --bind-try | --dev-bind | \
            --dev-bind-try | --symlink | --setenv | \
            --file | --bind-data | --ro-bind-data)
            echo 2
            ;;
        --dir | --tmpfs | --proc | --dev | --unsetenv | --chdir | --hostname)
            echo 1
            ;;
        *)
            echo 1
            ;;
    esac
}

# _is_secret_env_var NAME
#   Return 0 (true) if the environment variable NAME is considered sensitive
#   and its value should be redacted in --dry-run output.  Covers API keys,
#   tokens, and credentials forwarded by the bw* wrappers.
_is_secret_env_var() {
    case "$1" in
        # Generic suffix patterns.  These already cover GH_TOKEN,
        # GITHUB_TOKEN, ANTHROPIC_FOUNDRY_API_KEY, AIFAPIM_API_KEY,
        # OPENAI_API_KEY, CODEX_API_KEY, and CODEX_ACCESS_TOKEN — all of which
        # end in one of these suffixes — so they need no explicit entries.
        *_API_KEY | *_ACCESS_TOKEN | *_SECRET | *_PASSWORD | *_TOKEN)
            return 0
            ;;
        # Prefixed GitHub tokens (e.g. GH_TOKEN_NSLS2): the suffix is the
        # token name, not the literal "_TOKEN", so *_TOKEN does not catch it.
        GH_TOKEN_*)
            return 0
            ;;
    esac
    return 1
}

print_dry_run() {
    local _BWRAP_BIN _ENV_BIN
    _BWRAP_BIN="$(command -v bwrap)"
    _ENV_BIN="$(resolve_env_bin)"

    # Mirror the exact invocation used by launch_sandbox:
    #   exec <env_bin> -i <vars> <bwrap_bin> <BWRAP_ARGS> -- <_TOOL_CMD> <TOOL_ARGS>
    # Note: the actual launch passes BWRAP_ARGS via `bwrap --args FD` (NUL-separated
    # on an inherited fd) to keep secrets out of /proc/<pid>/cmdline; this dry-run
    # output shows the arguments inline for human readability (with secrets redacted).
    printf "exec %s -i \\\\\n" "${_ENV_BIN}"
    printf "  HOME=%q \\\\\n"    "${_HOME}"
    printf "  USER=%q \\\\\n"    "${_USER}"
    printf "  LOGNAME=%q \\\\\n" "${_USER}"
    printf "  PATH=%q \\\\\n"    "/usr/bin:/bin"
    printf "  LANG=%q \\\\\n"    "${LANG:-C.UTF-8}"
    printf "  LC_CTYPE=%q \\\\\n" "${LC_CTYPE:-C.UTF-8}"
    printf "  %s \\\\\n" "${_BWRAP_BIN}"

    # Print bwrap arguments one flag-plus-values per line.  Each flag's
    # value count comes from _bwrap_flag_arity, so a value beginning with
    # "--" is grouped with its flag instead of being misread as a new flag.
    #
    # For --setenv NAME VALUE pairs where NAME matches a sensitive pattern
    # (_is_secret_env_var), VALUE is replaced with REDACTED so secrets are
    # not echoed to the terminal.  The actual launch_sandbox path always
    # passes the real values.
    #
    # All values are %q-quoted (bash's shell-quote format) so paths containing
    # single quotes, spaces, or other special characters produce a valid
    # pasteable shell command.  The REDACTED placeholder for secrets is kept
    # as a literal string (no quoting needed — it has no special characters).
    local i=0 arg _arity _j _varname
    while [[ $i -lt ${#BWRAP_ARGS[@]} ]]; do
        arg="${BWRAP_ARGS[$i]}"
        _arity="$(_bwrap_flag_arity "${arg}")"
        printf "    %q" "${arg}"
        i=$((i + 1))
        if [[ "${arg}" == "--setenv" && "${_arity}" -eq 2 ]]; then
            # First value is the variable name — always print it.
            if [[ $i -lt ${#BWRAP_ARGS[@]} ]]; then
                _varname="${BWRAP_ARGS[$i]}"
                printf " %q" "${_varname}"
                i=$((i + 1))
            fi
            # Second value is the variable value — redact if sensitive.
            if [[ $i -lt ${#BWRAP_ARGS[@]} ]]; then
                if _is_secret_env_var "${_varname}"; then
                    # REDACTED is a literal placeholder with no special chars;
                    # keep it unquoted for readability.
                    printf " REDACTED"
                else
                    printf " %q" "${BWRAP_ARGS[$i]}"
                fi
                i=$((i + 1))
            fi
        else
            for ((_j = 0; _j < _arity && i < ${#BWRAP_ARGS[@]}; _j++)); do
                printf " %q" "${BWRAP_ARGS[$i]}"
                i=$((i + 1))
            done
        fi
        printf " \\\\\n"
    done
    printf "    --"
    local _cmd_part
    for _cmd_part in "${_TOOL_CMD[@]}"; do printf " %q" "${_cmd_part}"; done
    local _arg
    for _arg in ${TOOL_ARGS[@]+"${TOOL_ARGS[@]}"}; do printf " %q" "${_arg}"; done
    printf "\n"
    exit 0
}

# Launch bwrap itself with a scrubbed environment so /proc/1/environ
# does not leak host variables (SSH_AUTH_SOCK, DBUS_SESSION_BUS_ADDRESS, etc.).
#
# `env` is resolved via resolve_env_bin (prefers /usr/bin/env) rather than
# via PATH lookup at exec time — this prevents a user shell script named
# "env" earlier on PATH from hijacking the launch.  See resolve_env_bin.
#
# Security: BWRAP_ARGS is passed via `bwrap --args FD` (NUL-separated args
# on an inherited fd) rather than argv to keep secrets out of /proc/<pid>/cmdline.
# Forwarded credentials (ANTHROPIC_FOUNDRY_API_KEY, AIFAPIM_API_KEY, OPENAI_API_KEY,
# GH_TOKEN*, COPILOT_*, etc.) are placed in BWRAP_ARGS as `--setenv NAME VALUE`,
# and bwrap stays resident as the session supervisor — so without --args FD,
# any local user can read the tokens via `ps auxww` for the sandbox's entire
# lifetime.  The tool command and its arguments stay on the command line (they
# contain no secrets), only the bwrap configuration moves to the fd.
launch_sandbox() {
    local _BWRAP_BIN _ENV_BIN
    _BWRAP_BIN="$(command -v bwrap)"
    _ENV_BIN="$(resolve_env_bin)"

    if [[ "${HAS_ARGS_FD}" -eq 1 ]]; then
        # Modern path: stage BWRAP_ARGS in a temporary file (mode 0600), open it
        # as an fd, unlink the path immediately (data stays alive via the open fd),
        # then pass the fd to bwrap via --args.  This keeps secrets out of
        # /proc/<pid>/cmdline.
        local _args_fd _staged_args _arg _old_umask
        # Create a 0600 temp file (mktemp creates mode 0600 by default, but we
        # set umask 077 to be explicit and defend against any mktemp that might
        # honor a permissive umask).  Save and restore the umask to avoid
        # side effects.
        _old_umask="$(umask)"
        umask 077
        _staged_args="$(mktemp --tmpdir bwrap-args.XXXXXX)"
        umask "${_old_umask}"
        # Write each BWRAP_ARGS element as a NUL-separated record.
        for _arg in ${BWRAP_ARGS[@]+"${BWRAP_ARGS[@]}"}; do
            printf '%s\0' "${_arg}"
        done > "${_staged_args}"
        # Open the file read-only as an fd, then immediately unlink it.
        # The kernel keeps the data alive via the open fd; the filename
        # disappears from /tmp so there is nothing to clean up on exit or signal.
        exec {_args_fd}< "${_staged_args}"
        rm -f "${_staged_args}"
        # Launch bwrap with --args FD; the tool command stays on argv.
        exec "${_ENV_BIN}" -i \
            HOME="${_HOME}" \
            USER="${_USER}" \
            LOGNAME="${_USER}" \
            PATH="/usr/bin:/bin" \
            LANG="${LANG:-C.UTF-8}" \
            LC_CTYPE="${LC_CTYPE:-C.UTF-8}" \
            "${_BWRAP_BIN}" --args "${_args_fd}" -- "${_TOOL_CMD[@]}" ${TOOL_ARGS[@]+"${TOOL_ARGS[@]}"}
    else
        # Fallback for bwrap < 0.1.7 (well below the 0.4.0 floor, extremely unlikely):
        # pass BWRAP_ARGS via argv.  This exposes secrets in /proc/<pid>/cmdline for
        # the sandbox's entire lifetime — any local user can read them via ps.
        exec "${_ENV_BIN}" -i \
            HOME="${_HOME}" \
            USER="${_USER}" \
            LOGNAME="${_USER}" \
            PATH="/usr/bin:/bin" \
            LANG="${LANG:-C.UTF-8}" \
            LC_CTYPE="${LC_CTYPE:-C.UTF-8}" \
            "${_BWRAP_BIN}" "${BWRAP_ARGS[@]}" -- "${_TOOL_CMD[@]}" ${TOOL_ARGS[@]+"${TOOL_ARGS[@]}"}
    fi
}
