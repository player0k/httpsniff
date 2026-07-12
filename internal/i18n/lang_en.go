package i18n

// en — канонический каталог (английский). Служит фолбеком и эталоном ключей.
var en = map[string]string{
	// флаги командной строки
	"flag.port":            "proxy listen port",
	"flag.addr":            "proxy listen address (host)",
	"flag.pid":             "capture only traffic of the process with this PID (0 = all processes)",
	"flag.caCert":          "path to the CA certificate (your own or generated)",
	"flag.caKey":           "path to the CA private key",
	"flag.maxBody":         "max body bytes to print (0 = unlimited)",
	"flag.insecure":        "do not verify upstream server certificates",
	"flag.systemProxy":     "automatically enable the system proxy (capture out of the box)",
	"flag.transparent":     "transparent capture (WinDivert on Windows / iptables on Linux / pf on macOS)",
	"flag.quic":            "capture HTTP/3 (QUIC/UDP) — requires transparent mode",
	"flag.transparentPort": "transparent TCP capture port",
	"flag.quicPort":        "UDP port for QUIC capture",
	"flag.logFile":         "duplicate capture to a file (without ANSI colors)",
	"flag.noTUI":           "disable the TUI, stream the log",
	"flag.tlsMITM":         "in transparent mode, decrypt HTTPS (MITM); otherwise only SNI host + passthrough",
	"flag.lang":            "interface language: en, ru, fr, de, nl, es, pt (default: system)",

	// сообщения main
	"main.errCAInit":       "CA initialization error: %v",
	"main.errLogOpen":      "Could not open log file: %v",
	"main.errProxy":        "Proxy error: %v",
	"main.warnSysProxy":    "⚠ Could not enable the system proxy: %v",
	"main.warnTransparent": "⚠ Transparent mode unavailable: %v",
	"main.warnQUIC":        "⚠ QUIC capture unavailable: %v",
	"main.shutdown":        "Shutting down, restoring settings…",
	"main.restored":        "System proxy settings restored.",

	// справка (usage)
	"usage.header": `httpsniff — HTTP/HTTPS traffic interceptor (MITM proxy) for Windows, Linux and macOS

Usage:
  httpsniff [flags]
  httpsniff winconfig <list|exempt-all|exempt STRING|clear>   (Windows only)
  httpsniff unpin --pid <PID> [--apply|--auto]   disable TLS verification of a Flutter app
  httpsniff restore                         restore proxy settings after a crash

Capture out of the box (no manual proxy setup in the client):
  httpsniff                       # the system proxy is enabled automatically
  httpsniff --transparent         # + transparent capture (WinDivert/iptables, needs admin)
  httpsniff --quic                # + HTTP/3 (QUIC) capture, implies --transparent

Flags:
`,
	"usage.footer": `
How to use:
  1. Run httpsniff — on first run a CA is generated (ca-cert.pem).
  2. Install ca-cert.pem into the OS/browser trusted root certificate authorities.
  3. Traffic goes through the interceptor automatically (system proxy). For apps that
     ignore the system proxy, add --transparent (requires administrator rights).
  4. (Optional) Limit capture to a single process via --pid <PID>.

Windows 11 — access for AppContainer apps (UWP/WinUI/Store) to the proxy:
  httpsniff winconfig exempt-all   # allow loopback for all (Fiddler's WinConfig equivalent)

`,

	// баннер запуска
	"banner.title":           "httpsniff — HTTP/HTTPS/2/3 traffic interception",
	"banner.platform":        "Platform",
	"banner.proxy":           "Proxy",
	"banner.pidFilter":       "PID filter",
	"banner.pidNone":         "(none — capturing all processes)",
	"banner.caCert":          "CA cert",
	"banner.protocols":       "Protocols",
	"banner.mode":            "Mode",
	"banner.logFile":         "Log file",
	"banner.modeSystem":      "system proxy",
	"banner.modeExplicit":    "explicit proxy",
	"banner.modeTransparent": " + transparent",
	"banner.caWarn":          "⚠ A new CA was generated. Install it into the trusted root\n    certificate authorities, otherwise HTTPS clients will complain about the certificate.",
	"banner.installWin":      "Windows: certutil -addstore -f \"ROOT\" %s",
	"banner.installLinux":    "Linux (Debian/Ubuntu): sudo cp %s /usr/local/share/ca-certificates/httpsniff.crt && sudo update-ca-certificates",
	"banner.installMacOS":    "macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s",
	"banner.hotkeys":         "Hotkeys: p — set PID, a — all processes, s — status, q/Ctrl+C — quit.",

	// лог перехвата (render)
	"log.request":        "REQUEST",
	"log.response":       "RESPONSE",
	"log.requestBody":    "request body",
	"log.responseBody":   "response body",
	"log.bytes":          "bytes",
	"log.decoded":        "decoded: %s",
	"log.binary":         "[binary data, %d bytes, not shown]",
	"log.truncated":      "… truncated (%d of %d bytes)",
	"log.error":          "error: %v",
	"log.httpsNoDecrypt": "(not decrypted)",
	"log.httpsNote":      "body is encrypted; only the host (SNI) is shown. Decryption needs the app to trust our CA.",
	"log.mitmRejected":   "TLS MITM rejected by app for %s — certificate not trusted (run `unpin`); falling back to pass-through for this host",

	// интерфейс (ui)
	"ui.status":         "Filter: %s   [p] set PID   [a] all   [s] status   [q] quit",
	"ui.filterAll":      "all processes",
	"ui.filterPID":      "PID %d",
	"ui.logToFile":      "[logging to file]",
	"ui.captureAll":     "Capturing all processes.",
	"ui.help":           "Hotkeys: p — PID, a — all, s — status, q — quit",
	"ui.pidPrompt":      "PID (Enter — all processes): ",
	"ui.tuiLogTitle":    " httpsniff — log (↑/↓, PgUp/PgDn, mouse) ",
	"ui.tuiFilterTitle": " Filter by process ",
	"ui.tuiPidLabel":    " PID (empty = all): ",
	"ui.tuiError":       "TUI error:",

	// системный прокси (sysproxy)
	"sysproxy.hintWin":         "Windows system proxy enabled (WinINET). Browsers and apps that use\n  system settings will go through the interceptor automatically.",
	"sysproxy.hintLinux":       "GNOME system proxy enabled (gsettings). To capture outside GNOME\n  use --transparent (iptables REDIRECT).",
	"sysproxy.hintMacOS":       "macOS system proxy enabled (networksetup) on all active network services.\n  Apps that honor the system proxy go through the interceptor automatically.",
	"sysproxy.errGsettings":    "gsettings not found; use --transparent or set the proxy manually",
	"sysproxy.errNetworksetup": "networksetup not found; set the proxy manually in System Settings › Network",
	"sysproxy.errNoServices":   "no active network services found (networksetup)",
	"sysproxy.errUnsupported":  "automatic system proxy setup is not supported on this platform",

	// рантайм proxy (quic/transparent)
	"proxy.quicListen":                "  QUIC/HTTP-3 MITM listening on udp 127.0.0.1:%d (needs a UDP:443 redirect to this port)",
	"proxy.transparentWin":            "  Transparent capture via WinDivert active (TCP 80/443 → :%d)",
	"proxy.transparentLinux":          "  Transparent TCP listening on %s. Configure redirection, e.g.:\n    sudo iptables -t nat -A OUTPUT -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports %d",
	"proxy.transparentMacOS":          "  Transparent TCP listening on %s. Configure pf redirection, e.g.:\n    echo 'rdr pass on lo0 inet proto tcp to any port {80,443} -> 127.0.0.1 port %d' | sudo pfctl -ef -",
	"proxy.errPfOpen":                 "cannot open /dev/pf (transparent mode requires running as root)",
	"proxy.errTransparentUnsupported": "transparent mode is not supported on this platform",
	"proxy.errWinDivertMissing":       "WinDivert.dll not found next to the program; download WinDivert (https://reqrypt.org/windivert.html), put WinDivert.dll and WinDivert64.sys in the httpsniff folder. Falling back to the system proxy (--system-proxy)",
	"proxy.errAdmin":                  "transparent mode requires running as administrator",

	// подкоманда winconfig (только Windows)
	"wc.usage": `httpsniff winconfig — AppContainer loopback exemptions (Fiddler's WinConfig equivalent)

Commands:
  list                show all AppContainers and their exemption status
  exempt-all          allow loopback for ALL apps (Exempt All)
  exempt <string>     allow loopback for apps whose name/package contains <string>
  clear               remove all loopback exemptions

Requires administrator rights (except list).
`,
	"wc.needSubstr":    "specify an app name/package substring: httpsniff winconfig exempt <string>",
	"wc.error":         "Error:",
	"wc.enumErr":       "NetworkIsolationEnumAppContainers returned code %d",
	"wc.found":         "AppContainers found: %d (✓ = loopback allowed)",
	"wc.exemptCount":   "Exemptions now: %d",
	"wc.exemptAllDone": "✓ Exempt All: loopback allowed for %d apps.",
	"wc.noMatch":       "No apps found for \"%s\".",
	"wc.exemptDone":    "Done: added %d, %d exemptions total.",
	"wc.cleared":       "All loopback exemptions removed.",
	"wc.setErr":        "NetworkIsolationSetAppContainerConfig returned code %d ",
	"wc.setErrDenied":  "(access denied — run as administrator)",
	"wc.needAdmin":     "⚠ Administrator rights required. Run the console \"as administrator\".",

	// подкоманда unpin (только Windows)
	"up.needPid":    "specify --pid <PID> of the Flutter app",
	"up.needAdmin":  "⚠ Administrator rights are required to write to process memory.",
	"up.sigErr":     "signature error:",
	"up.moduleErr":  "flutter_windows.dll not found in process %d: %v",
	"up.moduleInfo": "flutter_windows.dll: base=0x%X size=%d",
	"up.openErr":    "OpenProcess: %v",
	"up.matches":    "signature matches: %d",
	"up.correcting": "function already patched by an older (return-0) build — correcting to return success (1)",
	"up.notFound":   "verification function not found — perhaps a different Flutter version (set your own --sig)",
	"up.multiple":   "multiple matches — not patching out of caution. Refine the signature (--sig).",
	"up.funcAddr":   "certificate verification function: 0x%X",
	"up.dryRun":     "(dry-run) add --apply to apply the patch",
	"up.patchErr":   "patch failed: %v",
	"up.patchOK":    "✓ TLS verification disabled. Now start capture with --tls-mitm.",
	"up.flagPid":    "PID of the Flutter app",
	"up.flagApply":  "apply the patch (without the flag — search/dry-run only)",
	"up.flagSig":    "signature of the verification function (hex, ?? — mask)",
	"up.flagAuto":   "auto mode: try all known signatures and apply",
	"up.flagDump":   "show function bytes before/after patch (diagnostics)",

	"up.autoStart":        "Auto mode: trying known Flutter/BoringSSL signatures…",
	"up.autoAlreadyPatched": "function already patched by older version (return 0) — correcting to return 1",
	"up.autoFound":        "✓ Found signature: %s — %s",
	"up.autoNotFound":     "no known signature matched — perhaps a very new Flutter version (set your own --sig)",
	"up.autoDryRun":       "(dry-run) add --apply to apply the patch",
}
