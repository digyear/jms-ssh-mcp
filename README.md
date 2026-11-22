# jms-ssh-mcp

[![npm](https://img.shields.io/npm/v/jms-ssh-mcp.svg)](https://www.npmjs.com/package/jms-ssh-mcp)

An MCP server for SSH bastions that do more than SSH: **password + TOTP**, then a **menu** where you pick a host, then a **persistent shell** on that host.

The agent's whole interface is *host + command*. Connections, menu navigation, OTP and re-login happen inside the server, keyed by host.

```
jms_ssh_run("10.0.0.15", "journalctl -n 200 --no-pager")
  → { "host": "10.0.0.15", "exitCode": 0, "output": "…" }
```

JumpServer (KoKo) is the reference target, but any bastion with a line-oriented menu works.

## Why another SSH MCP

Generic SSH MCP servers assume the connection is the destination: connect, run, disconnect. Behind a bastion that model breaks in three places, and none of them is a prompt-engineering problem:

| Reality | What generic servers do | What this one does |
|---|---|---|
| Second factor after the password | answer `keyboard-interactive` with the password or an empty string → the handshake hangs until timeout | classifies the prompt (`otp`, `one-time code`, `verification code`, `token` …) and computes TOTP at submit time |
| A menu owns stdin | `exec_command` is answered by the bastion locally, commands never reach the host | opens an interactive shell channel (`shell()`), not exec |
| Re-login costs an OTP round | connect per command | one login per host, many commands, closed on purpose |

Four details that cost real debugging time and are encoded here:

- **KoKo submits on `\r`, never `\n`.** With LF the menu echoes the digits and swallows them; nothing is selected and every later command lands in the menu.
- **The menu renders before you type at it.** The answer waits for the menu text, not for a fixed sleep, and the wait must not clear what was already buffered.
- **Menu options 1–11 are commands** (`2` = search, `9` = language), so a small asset id is consumed by the menu instead of selecting the asset.
- **A search result is answered with row numbers**, not asset ids — so a hostname matching several assets is reported as ambiguous instead of guessed.

## Tools (4)

| Tool | Purpose |
|---|---|
| `jms_ssh_run(host, command, account?, timeoutMs?, maxBytes?)` | Run a command; returns `{host, exitCode, output}` |
| `jms_ssh_hosts(filter?, limit?, scope?)` | The assets this account can reach, parsed |
| `jms_ssh_connections()` | Which hosts currently have a live connection |
| `jms_ssh_close(host?)` | Close one host, or all |

`host` accepts an asset id, IP or hostname; every spelling of the same asset reuses one connection, and no tool ever asks for a session id.

Logs are read with `jms_ssh_run` — there is no separate log tool, because it would only duplicate what the shell already does:

```
jms_ssh_run(host, "tail -n 200 /var/log/messages")
jms_ssh_run(host, "journalctl -u myapp -n 500 --no-pager --since '2 hours ago'")
jms_ssh_run(host, "tail -n 5000 /var/log/app.log | grep -E 'ERROR|timeout'")
```

Trimming on the target (`-n`, `--since`, `grep`) is what keeps both the transfer and the buffer small.

### Direct asset login skips the menu entirely

JumpServer accepts `<login>@<system user>@<asset>` as the SSH username and drops
you straight onto the target shell — no menu, no asset search, no row numbers:

```
jms_ssh_run("10.0.0.15", "hostname", account: "root")
  → connects as alice@root@10.0.0.15, lands on [root@web-01 ~]# in 1.4 s
```

Everything the menu path has to work around (waiting for menu text, CR submits,
option digits that collide with asset ids, search-result row numbers) simply does
not exist on this path. It is used whenever `account` is given; omit it and the
server falls back to the menu, which is still the only way in when the account is
not permitted to pick its own system user. A wrong account fails with the
bastion's own words ("no such user: nosuchuser").

### Why the exit code is real

The command is fenced with a random marker that carries `$?`:

```
journalctl -n 5 --no-pager
printf '\n__JMS9f2c1a7b__%s\n' "$?"
```

The runner waits for `__JMS9f2c1a7b__0` and splits output from that marker. Prompt-scraping can never tell you whether a command succeeded; this can, and it does not care what the prompt looks like on the far side of the menu.

## Memory

A `journalctl` or `cat` on a busy host can emit gigabytes, so the shell buffer is a **bounded window** (`JMS_SSH_MAX_BUFFER_CHARS`, default 4 MB): a small head, a rolling tail, and a counter of what was dropped. Output past it is discarded as it arrives, not after it is stored. The returned text is capped separately (`JMS_SSH_MAX_OUTPUT_BYTES`, default 256 KB, head + tail kept, `truncated: true` when it is cut).

Three limits, all on the reply rather than on hope:

| Limit | Default | What it protects |
|---|---|---|
| buffer per shell | 4 MB | the process |
| returned output | 256 KB | the caller's context |
| serialized reply | 1 MiB (`JMS_SSH_MAX_RESULT_BYTES`) | the bastion host: the JSON that actually crosses the transport, *after* escaping |

The last one matters because escaping is not free: a NUL byte becomes six bytes of JSON, so a binary file read as text could inflate a reply by an order of magnitude. Control characters no log needs are stripped, and output that is mostly binary is reported as `binary: true` instead of being handed over.

Measured: 400 000 log lines (~56 MB) → 5.8 s, 262 KB returned, buffer held 4.19 MB, dropped 52.4 MB, process RSS 90 → 156 → 90 MB. A 500 MB `cat` peaks at 195 MB RSS and returns 0.2 KB (`binary: true`).

If a command outlives its timeout it is interrupted with Ctrl-C and the shell is returned to its prompt, so the next `jms_ssh_run` on that host is not queued behind a command that never ends.

## Connections

- **One login per host.** A later call costs one round-trip (~0.2 s) instead of a login (~1.5 s).
- **Concurrent calls collapse.** Two callers asking for the same host at the same instant share one in-flight login instead of racing two OTP rounds.
- **One command at a time per host.** A single shell means a single stdin: calls against one connection are queued so two commands cannot interleave.
- **Different hosts are different connections**, capped by `JMS_SSH_MAX_SESSIONS` (default 8, least recently used evicted).
- **Drops heal.** A dead socket reconnects once and retries; `exit` on the target (back to the bastion prompt without dropping SSH) is detected and the asset is re-entered on the next call.
- **Idle reaping is off by default** (`JMS_SSH_IDLE_TIMEOUT_MS=0`): every re-login burns an OTP, so dropping an idle shell is a cost, not hygiene. Keepalives every 15 s surface a dead link instead of hanging.

## Configuration

Everything is reachable from the environment, because a container platform
(mcphub and friends) gives you an env block and nowhere to put a file. A config
file is optional and only useful when you have several bastions.

```bash
export JMS_SSH_HOST=jumpserver.example.com
export JMS_SSH_PORT=2222
export JMS_SSH_USERNAME=alice
export JMS_SSH_PASSWORD=...                  # or JMS_SSH_PASSWORD_ENV=MY_SECRET_VAR
export JMS_SSH_OTP_SECRET=JBSWY3DPEHPK3PXP   # base32 seed; or JMS_SSH_OTP_SECRET_ENV=...
export JMS_SSH_ACCOUNT=root                  # optional: log in directly as alice@root@asset
```

Env wins over the file for the same key; keys the env does not mention keep the
file value.

### Bastion

| Variable | Default | Note |
|---|---|---|
| `JMS_SSH_HOST` | — | required |
| `JMS_SSH_PORT` | `2222` | |
| `JMS_SSH_USERNAME` | — | required |
| `JMS_SSH_PASSWORD` | — | or `JMS_SSH_PASSWORD_ENV` naming another variable |
| `JMS_SSH_PASSWORD_ENV` | — | keeps the secret out of the process env block |
| `JMS_SSH_OTP_SECRET` | — | base32 seed or a whole `otpauth://` URI |
| `JMS_SSH_OTP_SECRET_ENV` | — | as above, by reference |
| `JMS_SSH_ACCOUNT` | — | default system user for every `jms_ssh_run`; a per-call `account` wins |
| `JMS_SSH_PRIVATE_KEY_PATH` | — | key auth instead of a password |
| `JMS_SSH_PASSPHRASE` | — | for an encrypted key |
| `JMS_SSH_MENU_PROMPT` | `Opt>\s*$` | the bastion's menu prompt |
| `JMS_SSH_LIST_PROMPT` | `\[(Host\|Node\|Asset\|…)\]>\s*$` | prompt of the paged asset list |
| `JMS_SSH_SHELL_PROMPT` | `[#$]\s*$` | prompt on the target host |
| `JMS_SSH_ENTER_KEY` | `cr` | `cr`, `lf`, or a char code; KoKo needs `cr` |
| `JMS_SSH_MCP_CONFIG` | — | path to a multi-bastion file instead of the keys above |

### Behaviour

| Variable | Default | Note |
|---|---|---|
| `JMS_SSH_COMMAND_TIMEOUT_MS` | `30000` | per command |
| `JMS_SSH_CONNECT_TIMEOUT_MS` | `20000` | login + menu navigation |
| `JMS_SSH_IDLE_TIMEOUT_MS` | `0` | 0 = keep connections until closed |
| `JMS_SSH_KEEPALIVE_MS` | `15000` | surfaces a dead link instead of hanging |
| `JMS_SSH_RECONNECT` | on | `0` disables the one automatic retry |
| `JMS_SSH_MENU_OPTION_MAX` | `11` | highest number the menu itself owns |
| `JMS_SSH_MAX_SESSIONS` | `8` | concurrent host connections, LRU eviction |
| `JMS_SSH_MAX_OUTPUT_BYTES` | `262144` | what the tool returns |
| `JMS_SSH_MAX_RESULT_BYTES` | `1048576` | cap on the serialized JSON reply |
| `JMS_SSH_MAX_BUFFER_CHARS` | `4194304` | what the process holds per shell |
| `JMS_SSH_DEBUG` | off | prompt and timing lines on stderr |

### Guard and audit

| Variable | Default | Note |
|---|---|---|
| `JMS_SSH_ALLOW_ALL` | off | disable the read-only allowlist |
| `JMS_SSH_ALLOWED_COMMANDS` | read-only set | comma-separated names or regexes |
| `JMS_SSH_ALLOWED_PREFIXES` | `sudo journalctl`, `docker logs`, `kubectl get`, … | comma-separated prefixes |
| `JMS_SSH_AUDIT_LOG` | unset | JSONL trail of every attempt, refusals included |
| `JMS_SSH_AUDIT_OUTPUT` | off | include the output text in the trail |

The seed is the `secret=` value of the authenticator QR: `otpauth://totp/JumpServer:alice?secret=JBSWY3DPEHPK3PXP`. [`src/totp.js`](src/totp.js) parses that URI, so pasting the whole URL works too.

`jms_ssh_hosts` always needs the menu, so when a default `account` sends
`jms_ssh_run` straight to the target, the first listing opens a second
connection in the background (one extra login, then reused).

## Security

- **Read-only by default.** `jms_ssh_run` checks every pipe segment against an allowlist (`cat`, `tail`, `journalctl`, `grep`, `df`, `ps`, `docker logs`, `kubectl logs` …); `rm`, editors and shells are refused.
- **No second command behind the first.** `;`, `&&`, `||`, backticks, `$(` and redirection are refused while the allowlist is on — `hostname; id` used to pass a first-word check and run as root. `|` is allowed, and each segment is validated on its own. `2>&1` and `2>/dev/null` pass.
- **Prefix rules are not wildcards.** `sudo journalctl` is allowed, bare `sudo` is not.
- `JMS_SSH_ALLOW_ALL=1` turns the guard off — only for a bastion account that is itself restricted.
- **Secrets never travel in tool arguments.** They come from env vars or the config file; results and errors are redacted.
- **The bastion is the real boundary.** An account that can log in as root on the target can do root things; scope the bastion account to the hosts it should see.
- **Audit exists twice.** JumpServer records the session; the server can write its own structured trail.

## Audit log

Point `JMS_SSH_AUDIT_LOG` at a file and every command attempt appends one JSON line — refusals included, because "who tried what" is the interesting half:

```bash
export JMS_SSH_AUDIT_LOG=/var/log/jms-mcp/audit.jsonl
```

```json
{"ts":"2026-11-20T09:57:36.395Z","pid":1234,"client":"hermes-desktop","host":"10.0.0.15","command":"hostname","outcome":"ok","exitCode":0,"ms":1154,"outputBytes":11}
{"ts":"2026-11-20T09:57:37.707Z","pid":1234,"client":"hermes-desktop","host":"10.0.0.15","command":"hostname; id","outcome":"refused","reason":"Shell control operators are not allowed…","ms":0}
```

- Written where the tool runs, not by the client, so a client that forgets cannot skip it.
- Output text is **not** recorded, only its size: logs contain secrets more often than anyone expects. `JMS_SSH_AUDIT_OUTPUT=1` opts in.
- `client` is the MCP client's own `clientInfo`, so several agents can share one file.
- Append-only, 0600, one write per call. Rotate with logrotate; nothing is re-read.

## How this compares

| Project | Shape | What we took |
|---|---|---|
| [classfang/ssh-mcp-server](https://github.com/classfang/ssh-mcp-server) (~1k★) | 6 tools: execute/upload/download/read-file/write-file/list-servers; `exec` mode with SFTP and `shell` mode with a persistent shell and command queue | the allowlist hardening: control operators refused, pipes validated per segment |
| [uarlouski/ssh-mcp-server](https://github.com/uarlouski/ssh-mcp-server) | production-leaning: command+argument whitelist, SFTP, JSONL audit log, imports `~/.ssh/config`, command aliases | audit log is the next thing worth adding |
| [hypnosis/ssh-mcp-server](https://github.com/hypnosis/ssh-mcp-server) | 18 purpose-built tools (jobs, log_tail, log_search, snapshot, audit baseline, TLS check) and structured answers that state what was truncated | the "say what you could not measure" habit; a job model for long commands |
| [Shadow-linux/jumpserver_ssh_mcp](https://github.com/Shadow-linux/jumpserver_ssh_mcp) | JumpServer gateways with per-entrance adapters, `file_push`/`file_pull` over Koko SFTP | confirms that per-entrance adapters are the hard part, not SSH itself |
| [lanchenglin/jumpserver-mcp](https://github.com/lanchenglin/jumpserver-mcp) | JumpServer REST API tools generated from `swagger.json`, plus SSH/SFTP using `{gateway_user}@{system_user}@{asset_ip}` | the direct-login username format above |

The one thing none of them solve is the menu itself — they either assume direct
SSH or go through JumpServer's API. Keeping both login paths is what makes this
server usable on a locked-down bastion *and* fast where direct login is allowed.

## Install

Node 20+. Three ways, all of them stdio — there is nothing to host.

### npx, no clone

```bash
npx -y jms-ssh-mcp --help
```

The same command also runs the current main branch without any registry involved:

```bash
npx -y github:digyear/jms-ssh-mcp --help
```

### Client configuration

Any client that speaks MCP over stdio, mcphub and Claude Desktop included:

```json
{
  "mcpServers": {
    "jms-ssh-mcp": {
      "command": "npx",
      "args": ["-y", "jms-ssh-mcp"],
      "env": {
        "JMS_SSH_HOST": "bastion.example.com",
        "JMS_SSH_PORT": "2222",
        "JMS_SSH_USERNAME": "alice",
        "JMS_SSH_PASSWORD": "<password>",
        "JMS_SSH_OTP_SECRET": "<base32 seed>"
      }
    }
  }
}
```

Use `["-y", "github:digyear/jms-ssh-mcp"]` to track main instead of a release. If
you would rather not put the secrets in the client's config, point at environment
variables instead:

```json
"env": { "JMS_SSH_HOST": "...", "JMS_SSH_USERNAME": "...",
         "JMS_SSH_PASSWORD_ENV": "BASTION_PASSWORD",
         "JMS_SSH_OTP_SECRET_ENV": "BASTION_OTP_SECRET" }
```

Every other setting — timeouts, byte caps, the command allowlist, the host
whitelist, the audit log — is an environment variable too, listed above.

### Global install

```bash
npm install -g jms-ssh-mcp
```

then use `"command": "jms-ssh-mcp"` in the client config.

### From source

```bash
git clone https://github.com/digyear/jms-ssh-mcp.git
cd jms-ssh-mcp
npm install
node src/index.js --help
```

## Layout

```
src/index.js     MCP surface: 4 tools, host-keyed connection registry
src/session.js   one bastion session: TOTP login, menu/asset selection, marker-fenced exec
src/window.js    bounded output window (head + rolling tail + dropped counter)
src/menu.js      asset table and page footer parsing
src/config.js    env/config-file resolution, command allowlist
src/totp.js      RFC 6238 (no dependency)
test/            TOTP vectors, menu parsing, window bounds, tool-surface contract
```

`npm test` runs the unit suite offline (42 tests). A live run needs a reachable bastion:

```bash
JMS_SSH_HOST=... JMS_SSH_USERNAME=... JMS_SSH_PASSWORD_ENV=... JMS_SSH_OTP_SECRET_ENV=... node src/index.js
```

MIT licensed.