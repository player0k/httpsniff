# httpsniff

HTTP/HTTPS traffic interceptor (MITM proxy) in Go for **Windows 10/11**, **Linux**, and **macOS**.

Decrypts HTTPS, displays **URL, headers, and decoded body** of requests and
responses. Works **out of the box** — automatically enables system proxy, so
no manual proxy configuration is needed in each client. Supports **HTTP/1.0, HTTP/1.1,
HTTP/2**, and **HTTP/3 (QUIC)**. Can filter capture by **process PID**.

## Features

- MITM HTTP and HTTPS with on-the-fly TLS substitution.
- **Out-of-the-box capture**: the program automatically enables system proxy on startup and
  restores settings on exit (and after crashes — see `restore`).
- **Protocol versions**: HTTP/1.0, HTTP/1.1, HTTP/2 (ALPN h2), HTTP/3 (QUIC).
- Custom CA: generated automatically or use your own
  (`--ca-cert` / `--ca-key`).
- Displays URL, all headers, and body in both directions.
- Body decompression for display: `gzip`, `deflate` (zlib/raw), `br` (brotli).
- PID-based filtering (`--pid`): Windows — `GetExtendedTcpTable`;
  Linux — `/proc/net/tcp{,6}` + `/proc/<pid>/fd`; macOS — `lsof` + `ps`. Matches
  **entire process tree** (target PID and all descendants — important for applications with
  child processes).
- Transparent per-PID capture via **WinDivert** (Windows) with **SNI** extraction
  for HTTPS — see where the application connects even without decryption.
- **Interactive hotkeys** — change PID filter on the fly without restarting.
- **TUI**: scrollable log on top and fixed status bar at the bottom — packet
  stream doesn't interrupt hotkey input. Modal PID input.
- **Log to file** (`--log-file`) — duplicate capture without ANSI colors.
- Transparent mode: Linux — iptables REDIRECT + `SO_ORIGINAL_DST`; macOS — pf `rdr` +
  ioctl `DIOCNATLOOK` on `/dev/pf`.
- System proxy out of the box: Windows — WinINET; Linux — GNOME `gsettings`;
  macOS — `networksetup` for all active network services.

## Capture Modes

| Mode | Flag | What it does | Requirements |
|------|------|-------------|-------------|
| System proxy | `--system-proxy` (enabled by default) | Automatically sets system proxy; catches all applications that respect it. QUIC clients disable themselves → HTTP/3 falls back to TCP and gets captured. | — |
| Explicit proxy | `--system-proxy=false` | Client is configured to use proxy manually. | — |
| Transparent | `--transparent` | Redirects all TCP, even from applications ignoring proxy. | Linux: iptables + root. Windows: WinDivert (see below). macOS: pf `rdr` + root. |
| HTTP/3 (QUIC) | `--quic` | MITM QUIC/UDP:443. | Transparent UDP redirect. |

## Building

Entry point is package `./cmd/httpsniff` (code is split across `internal/*` packages).

```sh
# Current OS
go build -o httpsniff ./cmd/httpsniff

# Cross-compilation
GOOS=windows GOARCH=amd64 go build -o httpsniff.exe ./cmd/httpsniff
GOOS=linux   GOARCH=amd64 go build -o httpsniff     ./cmd/httpsniff
GOOS=darwin  GOARCH=arm64 go build -o httpsniff     ./cmd/httpsniff   # Apple Silicon
GOOS=darwin  GOARCH=amd64 go build -o httpsniff     ./cmd/httpsniff   # Intel Mac

# Tests and static analysis
go test ./...
go vet ./...
```

## Usage

### Basic Examples

```sh
# Start with automatic system proxy (catches most applications)
./httpsniff

# Capture traffic from a specific process by PID
./httpsniff --pid 12345

# Log capture to file (without ANSI colors)
./httpsniff --log-file capture.log

# Restore proxy settings after crash
./httpsniff restore
```

### Browser Traffic

```sh
# Chrome/Firefox/Edge — system proxy is set automatically
./httpsniff

# If browser ignores proxy, use transparent mode (Linux/macOS)
sudo ./httpsniff --transparent
```

### Command-line Tools

```sh
# curl respects system proxy by default
./httpsniff
curl https://example.com

# wget with explicit proxy
./httpsniff --port 9090
wget -e use_proxy=yes -e http_proxy=127.0.0.1:9090 https://example.com
```

### Flutter/Dart Applications

Flutter apps ignore system proxy and use their own certificate store (BoringSSL).
In transparent mode, HTTPS is **not decrypted** by default, but SNI host is shown.

```sh
# 1. Find Flutter app PID (Task Manager or ps)
# Windows:
tasklist | findstr flutter
# Linux/macOS:
ps aux | grep flutter

# 2. Start capture with transparent mode (SNI only, no decryption)
sudo ./httpsniff --transparent --pid <PID>

# 3. For full decryption — use unpin (see "Flutter/Dart" section below)
```

### Windows: UWP/WinUI Apps

Windows 11 isolates UWP apps in AppContainer. Allow loopback first:

```sh
# Allow all apps (requires admin)
httpsniff winconfig exempt-all

# Or allow specific app
httpsniff winconfig exempt MyAppName

# Then start capture
httpsniff
```

### HTTP/3 (QUIC) Capture

```sh
# Capture QUIC/UDP traffic (requires root/admin)
sudo ./httpsniff --quic

# Combined with transparent mode
sudo ./httpsniff --transparent --quic
```

### Custom CA Certificate

```sh
# Use your own CA for existing infrastructure
./httpsniff --ca-cert /path/to/ca.pem --ca-key /path/to/ca.key

# Generate new CA (default behavior)
./httpsniff  # creates ca-cert.pem and ca-key.pem
```

Flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8888` | proxy listening port |
| `--addr` | `127.0.0.1` | proxy listening address (host) |
| `--system-proxy` | `true` | automatically enable system proxy |
| `--transparent` | `false` | transparent capture (WinDivert / iptables / pf) |
| `--quic` | `false` | HTTP/3 (QUIC/UDP) capture |
| `--pid` | `0` | capture only this PID (0 = all) |
| `--ca-cert` | `ca-cert.pem` | CA certificate (custom or generated) |
| `--ca-key` | `ca-key.pem` | CA private key |
| `--max-body` | `8192` | max body bytes to display (0 = no limit) |
| `--insecure` | `false` | don't verify upstream server certificates |
| `--log-file` | — | duplicate capture to file (without ANSI colors) |
| `--no-tui` | `false` | disable TUI, stream log output |
| `--tls-mitm` | `false` | in transparent mode, decrypt HTTPS (MITM); otherwise SNI host + passthrough |
| `--lang` | — | interface language (default: system language) |

Subcommands: `httpsniff restore` — restore proxy settings; `httpsniff winconfig …` — AppContainer loopback exceptions (Windows only).

## Localization

Interface is translated into **7 languages**: English (`en`), Russian (`ru`), French
(`fr`), German (`de`), Dutch (`nl`), Spanish (`es`), Portuguese (`pt`).

Language is **auto-detected from system settings**, fallback is English:

- **Windows** — by user interface language (`GetUserDefaultUILanguage`).
- **Linux / macOS / other** — by POSIX environment variables: `LC_ALL`, then
  `LC_MESSAGES`, then `LANG` (e.g., `de_DE.UTF-8` → German).

Language can be explicitly set with `--lang` (overrides auto-detection):

```sh
httpsniff --lang fr            # French
LANG=es_ES.UTF-8 httpsniff     # Spanish via environment (Linux)
```

Strings are stored in Go catalogs in package [internal/i18n](internal/i18n/); adding
a language is a new catalog file `lang_<code>.go` with the same keys (completeness is verified
by `TestCatalogsComplete` test).

## Interface (TUI) and Hotkeys

When launched in a terminal, a TUI opens: scrollable capture log on top
(↑/↓, PgUp/PgDn, mouse), fixed status bar with filter and hotkeys at the bottom.
Packet stream goes to the upper area and **doesn't interrupt** hotkey input.

| Key | Action |
|-----|--------|
| `p` | open PID input → capture only that PID (empty — clear filter) |
| `a` | capture all processes |
| `s` | refresh status bar |
| `q` / Ctrl+C | exit with settings restored |

Log to file: `httpsniff --log-file capture.log` — all capture is duplicated to a file
without color codes (useful for grep/analysis).

If stdout is not a terminal or `--no-tui` is set, streaming mode is enabled with line-by-line
commands (`p <pid>`, `a`, `s`, `q`).

## How It Works

1. On first run, a root CA is generated (`ca-cert.pem`).
2. Install the CA in your OS/browser trusted root certificate store:
   - **Windows:** `certutil -addstore -f "ROOT" ca-cert.pem`
   - **Linux (Debian/Ubuntu):**
     `sudo cp ca-cert.pem /usr/local/share/ca-certificates/httpsniff.crt && sudo update-ca-certificates`
   - **macOS:**
     `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca-cert.pem`
3. Traffic flows through the interceptor automatically: system proxy is enabled on
   startup (by default), no manual client configuration needed. For applications
   that ignore system proxy, add `--transparent`.
4. The proxy issues a certificate signed by your CA for each domain on the fly,
   decrypts traffic (HTTP/1.x, HTTP/2, HTTP/3), logs it and forwards to the server.
5. For each TCP connection, the client process PID is determined (by ephemeral port).
   If `--pid` is set, other traffic is tunneled without decryption or logging.
6. On exit (Ctrl+C), system proxy is restored. After a crash, run
   `httpsniff restore` (or simply run again — it restores
   automatically from the state file).

## Windows 11: AppContainer Access (Fiddler WinConfig equivalent)

Windows 11 isolates UWP/WinUI/Store apps in AppContainer, so they
**can't see local (loopback) proxy**. Fiddler solves this with WinConfig →
Exempt All. The same is implemented here via the same network isolation API
(`FirewallAPI.dll` → `NetworkIsolation*`):

```sh
# view all AppContainers and their status (✓ = loopback already allowed)
httpsniff winconfig list

# allow loopback for ALL applications (requires admin)
httpsniff winconfig exempt-all

# allow only specific ones (by name/package substring)
httpsniff winconfig exempt Edge

# clear all exceptions
httpsniff winconfig clear
```

`exempt-all`, `exempt`, and `clear` modify the system loopback exception list and
require admin rights. `list` works without admin.

## Transparent Mode and HTTP/3

- **Linux** — implemented via iptables REDIRECT + `SO_ORIGINAL_DST`. Example rules
  are displayed when launching with `--transparent`. For QUIC, add REDIRECT for UDP:443.
- **macOS** — implemented via packet filter **pf**: `rdr` rule redirects
  TCP to the local interceptor port, and the original destination address is restored via
  ioctl `DIOCNATLOOK` on `/dev/pf` (similar to `SO_ORIGINAL_DST`,
  [transparent_darwin.go](internal/proxy/transparent_darwin.go)). Requires root.
  Example pf rule is displayed when launching with `--transparent`:
  ```sh
  echo 'rdr pass on lo0 inet proto tcp to any port {80,443} -> 127.0.0.1 port 8889' | sudo pfctl -ef -
  sudo httpsniff --transparent
  ```
- **Windows** — implemented on the **WinDivert** driver ([windivert_windows.go](internal/proxy/windivert_windows.go)):
  redirects outgoing TCP from selected processes (by PID/tree) to a local port using
  "dst=src" scheme, with server address restoration on the return path. Requires WinDivert
  driver (`WinDivert.dll` + `WinDivert64.sys` next to the program) and admin rights.
  Launch: `httpsniff --transparent --pid <PID>` (or without `--pid` — all traffic).

### HTTPS for Apps That Don't Trust Our CA (Flutter/Dart)

**Flutter/Dart** applications ignore system proxy and use **their own**
root certificate store (BoringSSL) — our CA is not trusted by them, normal MITM breaks
the connection. For them, in transparent mode by default (`--tls-mitm=false`) HTTPS
**is not decrypted**, but transparently passed through to the server; the log shows
**SNI host** — you can see where the app connects without breaking it.

**Full Flutter decryption (`unpin`).** If the application is not in AppContainer
sandbox (normally MSIX-packaged Flutter apps are not), you can disable TLS verification
with a memory patch: find the certificate chain verification function
(`ssl_crypto_x509_session_verify_cert_chain`) in `flutter_windows.dll` by its prologue
and replace it with "always succeed" (`mov eax,1; ret`). Technique from Frida scripts
[Anof-cyber](https://github.com/Anof-cyber/Flutter-Windows) /
[NVISO](https://github.com/NVISOsecurity/disable-flutter-tls-verification), but without Frida.

```sh
# 1) Check that the function is found (safe, read-only):
httpsniff unpin --pid <PID>
# 2) Auto mode: try all known signatures and apply:
httpsniff unpin --pid <PID> --auto --apply
# 3) Manual mode: specify signature manually:
httpsniff unpin --pid <PID> --apply --sig "41 57 41 56 41 55 41 54 56 57 53 48 83 EC 40 48 89 CF 48 8B 05 ?? ?? ?? ??"
# 4) Capture with decryption:
httpsniff --transparent --pid <PID> --tls-mitm --system-proxy=false
```

**`unpin` flags:**

| Flag | Description |
|------|-------------|
| `--pid` | Flutter app PID (required) |
| `--apply` | apply patch (without flag — dry-run) |
| `--auto` | auto mode: try all known signatures |
| `--sig` | verification function signature (hex, `??` — mask) |
| `--dump` | show function bytes before/after patch (diagnostics) |

Known signatures (tried in `--auto`):
- `flutter-3.x` — standard (Flutter 3.x, BoringSSL)
- `flutter-3.16+` — new BoringSSL
- `flutter-3.19+` — updated prologue
- `flutter-3.22+` — extended stack

## Limitations

- Client must trust your CA, otherwise it will show a certificate error.
- PID detection: Windows, Linux, and macOS; QUIC streams don't have PID detection yet.
- Full transparent capture on Windows requires WinDivert (see above).

## Dependencies

`golang.org/x/net/http2`, `github.com/quic-go/quic-go` (HTTP/3),
`github.com/andybalholm/brotli`, `github.com/rivo/tview` + `github.com/gdamore/tcell/v2` (TUI),
`golang.org/x/term`, `golang.org/x/sys`.

### Windows: WinDivert

For transparent capture on Windows, the program requires the **WinDivert** driver:
[https://github.com/basil00/WinDivert](https://github.com/basil00/WinDivert)

Place `WinDivert.dll` and `WinDivert64.sys` next to the `httpsniff.exe` binary.
These files can be downloaded from the [WinDivert releases](https://github.com/basil00/WinDivert/releases).
