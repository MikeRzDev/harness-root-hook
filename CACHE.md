# Password caching

Codex and Claude Code use the same cache implementation (built into `psudo`) and
JSON settings on Linux and macOS. **Caching is off by default**: every command
shows the dialog. When you turn it on (`"enabled": true`), harness-secrets-sudo-hook reuses a
**sudo password** that sudo accepted for a command on this computer for
`ttl_seconds` (7200, two hours). This is normally your own account password, not
a separate root password.

**Read this before turning it on.** The OS credential store doesn't keep the
password from other programs running as you. On macOS the Keychain entry trusts
`/usr/bin/security`. On Linux, an unlocked Secret Service returns it to any
client. So the harness's own shell can read it with one command
(`security find-generic-password -w …` or `secret-tool lookup …`), which would
put your password in the model's context. The Claude Code guard denies commands
that read `harness-root-hook` entries, but a guard can be worked around. Codex
has no deny hook at all.

**Only local commands are cached.** `psudo -H <host>` always shows the dialog,
and remote passwords are never stored. While a local password is cached, no
dialog appears, so the harness's own approval prompt is what shows you the
command.

The window starts at successful authentication. Repeated commands **do not extend
it**. At expiry, the next privileged command requests your password again. Each
harness has its own credential-store entry; authenticating Codex does not unlock
Claude Code's cache or vice versa. Harness approvals still apply to commands.

## Configuration

Both installers create this file if it is missing and preserve your edits:

```text
~/.config/harness-root-hook/config.json
```

```json
{
  "cache": {
    "enabled": false,
    "ttl_seconds": 7200
  }
}
```

See [config.example.json](config.example.json). The file contains settings only;
never put a password in it. `ttl_seconds` is an integer from 0 to 31536000.
Caching is on only when `enabled` is explicitly `true` and `ttl_seconds` is above
`0`. A missing file, a missing `enabled` key or `"enabled": false` all mean off.
Configs written by earlier versions say `"enabled": true` and keep caching until
you change them.

The path follows `XDG_CONFIG_HOME` when set. Set `HARNESS_ROOT_HOOK_CONFIG` to an
absolute JSON file path to override it. Set the override both during installation
and in the harness environment so the macOS cleanup task uses the same settings.
Both harnesses on a computer use this shared settings file.

Settings are read on every authentication request. Reducing the duration applies
to an existing entry immediately on its next use. Increasing it takes effect
when you next authenticate; it does not extend a previously issued cache entry.
Disabling caching clears that harness's entry on its next use. Invalid JSON,
unknown settings, and invalid values fail authentication instead of silently
using defaults. No legacy `CLAUDE_SUDO_TTL` override is used; migrate that setting
to the JSON file.

## OS-managed storage

| OS | Credential store | Requirements |
| --- | --- | --- |
| Linux | Desktop Secret Service, accessed through `secret-tool` | `libsecret-tools` and an active Secret Service provider such as GNOME Keyring |
| macOS | macOS Keychain, accessed through `/usr/bin/security` | Logged-in desktop session and an available default keychain |

Passwords are stored in the credential store's **secret value**, never its
search attributes or a plaintext password file. The store manages encryption and
unlocking; configure a password-protected login keyring/keychain. An OS keyring
unlock or permission prompt can still appear if the store is locked. Processes
with access to your unlocked credential store may retrieve its secrets.

Secrets pass to sudo and storage commands through stdin pipes, not command-line
arguments or log files. On macOS, an encoded record is sent over `security -i`'s
stdin; Keychain provides encryption, not the encoding. Runtime lock files are
empty and contain no passwords. Passwords necessarily exist briefly in process
memory while authenticating; this is not a hardware-backed credential scheme.

There is **no plaintext fallback** when the OS credential store is missing or
unavailable. Linux requires a working desktop D-Bus session. Missing dependency,
locked-store failure, or storage failure stops the authentication attempt.

A password is stored only after sudo has accepted it. If sudo rejects a cached
password, for example because you changed it, harness-secrets-sudo-hook deletes the entry and exits
252 without retrying; the next command shows the dialog. Cancellation aborts the
privileged action. harness-secrets-sudo-hook runs `sudo -k` before and after each command, so sudo's
separate timestamp cache cannot bypass the configured expiry.

Expired credentials are never reused. Linux removes expired entries on the next
cache request, so an unused expired entry can remain encrypted in the keyring
until it is cleared. macOS additionally installs a per-harness launchd cleanup
task every five minutes; when running successfully, it deletes expired entries
without reading their password values. Sleep and OS scheduling can delay cleanup,
but do not extend the authentication window. Clear entries explicitly when needed.

## Clear cached credentials

These commands delete credentials without printing them:

```sh
# Codex
"${CODEX_HOME:-$HOME/.codex}/root-hook/psudo" --clear-cache=codex

# Claude Code
"$HOME/.claude/hooks/psudo" --clear-cache=claude-code
```

Uninstalling a harness integration clears its cache and removes its macOS cleanup
task. The shared JSON configuration is retained for the other harness and future
installation. Uninstall while the credential store is available; a failed clear
is reported instead of pretending the credential was removed.

## Upgrading from the Python helper

`psudo --install=…` keeps the same Keychain service and Secret Service attributes
(`harness-root-hook.<harness>`) and record format, so a password cached by the
previous Python helper stays valid until its original deadline. The installer
removes `harness_cache.py` and the old shell hooks.

## Upgrading from the original Claude Code cache

Run `psudo --install=claude-code`. The Linux installer deletes the old
`claude-sudo.cache` plaintext file. The macOS installer removes the old
`claude-sudo` Keychain item and `com.claude.sudo-reaper` task. New entries use
`harness-root-hook` names, and the default changes from a sliding one-hour window
to a fixed two-hour window. Restart the harness after reinstalling.

## References

- [Secret Service API](https://specifications.freedesktop.org/secret-service/latest-single/)
- [GNOME secret-tool implementation](https://github.com/GNOME/libsecret/blob/main/tool/secret-tool.c)
- [Apple security tool and stdin command parsing](https://github.com/apple-oss-distributions/SecurityTool/blob/main/security.c)
