# Codex

Part of [Power Sudo Harness Hook](../README.md). For Claude Code, see the [Claude Code guide](../claude-code/README.md).

## Install

```sh
psudo --install=codex            # from a release archive: ./psudo --install=codex
# or from a source checkout:
make install-codex
```

This copies the binary to `$CODEX_HOME/root-hook/psudo` (default
`~/.codex/root-hook/psudo`) and merges a SessionStart hook into
`$CODEX_HOME/hooks.json`, keeping unrelated hooks. The first run backs the file
up to `hooks.json.before-root-hook`. The installer also creates the shared
`config.json` if missing and, on macOS, the
`com.harness-root-hook.codex.reaper` cleanup task.

Open `/hooks` in Codex, review and trust the hook, then start a new session. The
hook only adds context telling Codex to use psudo. It never runs sudo, prompts
for a password, or makes permission decisions. Codex's normal approval and
sandbox rules still apply.

## Usage

Ask Codex to perform the administrative task. Its commands should look like:

```sh
"${CODEX_HOME:-$HOME/.codex}/root-hook/psudo" id -u
"${CODEX_HOME:-$HOME/.codex}/root-hook/psudo" -H web1 systemctl restart nginx
```

A dialog shows the host and command. Enter your sudo password there, never in
chat. Local password caching is off by default (see the risk in CACHE.md); when
turned on, Codex has its own credential-store entry, separate from Claude Code's.
Remote hosts always prompt. See
[password caching](../CACHE.md).

For Codex versions without hooks, give Codex the helper's absolute path in your
prompt or `AGENTS.md`.

## Upgrading from `codex-sudo`

The installer removes `codex-sudo`, `askpass.sh`, `context.py` and
`harness_cache.py` and replaces the old `python3 …/context.py` hook registration.
`psudo` takes a command only, with no sudo options. Use
`psudo runuser -u <user> -- …` in place of `codex-sudo -u <user> …`. Update any
`AGENTS.md` that mentions `codex-sudo`.

## Uninstall

```sh
"${CODEX_HOME:-$HOME/.codex}/root-hook/psudo" --uninstall=codex
```
