package i18n

// de — немецкий каталог.
var de = map[string]string{
	"flag.port":            "Proxy-Lauschport",
	"flag.addr":            "Proxy-Lauschadresse (Host)",
	"flag.pid":             "nur Datenverkehr des Prozesses mit dieser PID erfassen (0 = alle Prozesse)",
	"flag.caCert":          "Pfad zum CA-Zertifikat (eigenes oder generiertes)",
	"flag.caKey":           "Pfad zum privaten CA-Schlüssel",
	"flag.maxBody":         "maximale Anzahl auszugebender Body-Bytes (0 = unbegrenzt)",
	"flag.insecure":        "Zertifikate der Upstream-Server nicht prüfen",
	"flag.systemProxy":     "System-Proxy automatisch aktivieren (Erfassung ohne Einrichtung)",
	"flag.transparent":     "transparente Erfassung (WinDivert unter Windows / iptables unter Linux / pf unter macOS)",
	"flag.quic":            "HTTP/3 (QUIC/UDP) erfassen — erfordert transparenten Modus",
	"flag.transparentPort": "Port der transparenten TCP-Erfassung",
	"flag.quicPort":        "UDP-Port der QUIC-Erfassung",
	"flag.logFile":         "Erfassung zusätzlich in eine Datei schreiben (ohne ANSI-Farben)",
	"flag.noTUI":           "TUI deaktivieren, Log als Stream ausgeben",
	"flag.tlsMITM":         "im transparenten Modus HTTPS entschlüsseln (MITM); sonst nur SNI-Host + Durchleitung",
	"flag.autoUnpin":       "mit --tls-mitm: TLS-Prüfung neuer Flutter-Prozesse automatisch deaktivieren (nur Windows; Standard an)",
	"flag.lang":            "Oberflächensprache: en, ru, fr, de, nl, es, pt (Standard: System)",

	"main.errCAInit":       "Fehler bei der CA-Initialisierung: %v",
	"main.errLogOpen":      "Log-Datei konnte nicht geöffnet werden: %v",
	"main.errProxy":        "Proxy-Fehler: %v",
	"main.warnSysProxy":    "⚠ System-Proxy konnte nicht aktiviert werden: %v",
	"main.warnTransparent": "⚠ Transparenter Modus nicht verfügbar: %v",
	"main.warnQUIC":        "⚠ QUIC-Erfassung nicht verfügbar: %v",
	"main.shutdown":        "Beende, stelle Einstellungen wieder her…",
	"main.restored":        "System-Proxy-Einstellungen wiederhergestellt.",
	"main.autoUnpinOn":     "auto-unpin: überwache neue Flutter-Prozesse (Windows)",

	"usage.header": `httpsniff — HTTP/HTTPS-Verkehrs-Interceptor (MITM-Proxy) für Windows, Linux und macOS

Verwendung:
  httpsniff [Optionen]
  httpsniff winconfig <list|exempt-all|exempt STRING|clear>   (nur Windows)
  httpsniff unpin --pid <PID> [--apply|--auto]   TLS-Prüfung einer Flutter-App deaktivieren
  httpsniff restore                         Proxy-Einstellungen nach Absturz wiederherstellen

Erfassung ohne Einrichtung (keine manuelle Proxy-Konfiguration im Client):
  httpsniff                       # der System-Proxy wird automatisch aktiviert
  httpsniff --transparent         # + transparente Erfassung (WinDivert/iptables, Admin nötig)
  httpsniff --quic                # + HTTP/3-(QUIC)-Erfassung, impliziert --transparent

Optionen:
`,
	"usage.footer": `
Verwendung:
  1. Starten Sie httpsniff — beim ersten Start wird ein CA generiert (ca-cert.pem).
  2. Installieren Sie ca-cert.pem in die vertrauenswürdigen Stammzertifizierungsstellen des OS/Browsers.
  3. Der Verkehr läuft automatisch über den Interceptor (System-Proxy). Für Apps, die den
     System-Proxy ignorieren, fügen Sie --transparent hinzu (Administratorrechte erforderlich).
  4. (Optional) Erfassung mit --pid <PID> auf einen einzelnen Prozess beschränken.

Windows 11 — Zugriff von AppContainer-Apps (UWP/WinUI/Store) auf den Proxy:
  httpsniff winconfig exempt-all   # Loopback für alle erlauben (Fiddlers WinConfig-Äquivalent)

`,

	"banner.title":           "httpsniff — Erfassung von HTTP/HTTPS/2/3-Verkehr",
	"banner.platform":        "Plattform",
	"banner.proxy":           "Proxy",
	"banner.pidFilter":       "PID-Filter",
	"banner.pidNone":         "(keiner — alle Prozesse werden erfasst)",
	"banner.caCert":          "CA-Zert.",
	"banner.protocols":       "Protokolle",
	"banner.mode":            "Modus",
	"banner.logFile":         "Log-Datei",
	"banner.modeSystem":      "System-Proxy",
	"banner.modeExplicit":    "expliziter Proxy",
	"banner.modeTransparent": " + transparent",
	"banner.caWarn":          "⚠ Ein neuer CA wurde generiert. Installieren Sie ihn in die vertrauenswürdigen\n    Stammzertifizierungsstellen, sonst bemängeln HTTPS-Clients das Zertifikat.",
	"banner.installWin":      "Windows: certutil -addstore -f \"ROOT\" %s",
	"banner.installLinux":    "Linux (Debian/Ubuntu): sudo cp %s /usr/local/share/ca-certificates/httpsniff.crt && sudo update-ca-certificates",
	"banner.installMacOS":    "macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s",
	"banner.hotkeys":         "Tasten: p — PID setzen, a — alle Prozesse, s — Status, q/Strg+C — beenden.",

	"log.request":        "ANFRAGE",
	"log.response":       "ANTWORT",
	"log.requestBody":    "Anfrage-Body",
	"log.responseBody":   "Antwort-Body",
	"log.bytes":          "Bytes",
	"log.decoded":        "dekodiert: %s",
	"log.binary":         "[Binärdaten, %d Bytes, nicht angezeigt]",
	"log.truncated":      "… gekürzt (%d von %d Bytes)",
	"log.error":          "Fehler: %v",
	"log.httpsNoDecrypt": "(nicht entschlüsselt)",
	"log.httpsNote":      "Body verschlüsselt; nur der Host (SNI) wird angezeigt. Entschlüsselung erfordert, dass die App unserem CA vertraut.",
	"log.mitmRejected":   "TLS-MITM von der App für %s abgelehnt — Zertifikat nicht vertrauenswürdig; Rückfall auf Pass-through für diesen Host",
	"log.mitmHintCA":     "pid %d ist kein Flutter — CA muss vertrauenswürdig sein (curl/Browser nutzen den Systemspeicher)",

	"ui.status":         "Filter: %s   [p] PID setzen   [a] alle   [s] Status   [q] beenden",
	"ui.filterAll":      "alle Prozesse",
	"ui.filterPID":      "PID %d",
	"ui.logToFile":      "[Schreiben in Datei]",
	"ui.captureAll":     "Alle Prozesse werden erfasst.",
	"ui.help":           "Tasten: p — PID, a — alle, s — Status, q — beenden",
	"ui.pidPrompt":      "PID (Enter — alle Prozesse): ",
	"ui.tuiLogTitle":    " httpsniff — Log (↑/↓, Bild↑/Bild↓, Maus) ",
	"ui.tuiFilterTitle": " Nach Prozess filtern ",
	"ui.tuiPidLabel":    " PID (leer = alle): ",
	"ui.tuiError":       "TUI-Fehler:",

	"sysproxy.hintWin":         "Windows-System-Proxy aktiviert (WinINET). Browser und Apps, die die\n  Systemeinstellungen verwenden, laufen automatisch über den Interceptor.",
	"sysproxy.hintLinux":       "GNOME-System-Proxy aktiviert (gsettings). Zum Erfassen außerhalb von GNOME\n  verwenden Sie --transparent (iptables REDIRECT).",
	"sysproxy.hintMacOS":       "macOS-System-Proxy aktiviert (networksetup) für alle aktiven Netzwerkdienste.\n  Apps, die den System-Proxy beachten, laufen automatisch über den Interceptor.",
	"sysproxy.errNetworksetup": "networksetup nicht gefunden; Proxy manuell unter Systemeinstellungen › Netzwerk setzen",
	"sysproxy.errNoServices":   "keine aktiven Netzwerkdienste gefunden (networksetup)",
	"sysproxy.errGsettings":    "gsettings nicht gefunden; verwenden Sie --transparent oder setzen Sie den Proxy manuell",
	"sysproxy.errUnsupported":  "die automatische System-Proxy-Einrichtung wird auf dieser Plattform nicht unterstützt",

	"proxy.quicListen":                "  QUIC/HTTP-3-MITM lauscht auf udp 127.0.0.1:%d (benötigt UDP:443-Umleitung auf diesen Port)",
	"proxy.transparentWin":            "  Transparente Erfassung über WinDivert aktiv (TCP 80/443 → :%d)",
	"proxy.transparentLinux":          "  Transparentes TCP lauscht auf %s. Umleitung einrichten, z. B.:\n    sudo iptables -t nat -A OUTPUT -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports %d",
	"proxy.transparentLinuxActive":    "  Transparentes TCP lauscht auf %s. iptables REDIRECT automatisch konfiguriert (TCP 80/443 → :%d). Regeln werden beim Beenden entfernt.",
	"proxy.errIptablesNotFound":       "iptables nicht gefunden; installieren Sie iptables oder richten Sie die Umleitung manuell ein",
	"proxy.errIptablesSetup":          "iptables REDIRECT konnte nicht eingerichtet werden: %s",
	"proxy.transparentMacOS":          "  Transparentes TCP lauscht auf %s. pf-Umleitung einrichten, z. B.:\n    echo 'rdr pass on lo0 inet proto tcp to any port {80,443} -> 127.0.0.1 port %d' | sudo pfctl -ef -",
	"proxy.errPfOpen":                 "/dev/pf kann nicht geöffnet werden (transparenter Modus erfordert root)",
	"proxy.errTransparentUnsupported": "der transparente Modus wird auf dieser Plattform nicht unterstützt",
	"proxy.errWinDivertMissing":       "WinDivert.dll nicht neben dem Programm gefunden; laden Sie WinDivert herunter (https://reqrypt.org/windivert.html), legen Sie WinDivert.dll und WinDivert64.sys in den httpsniff-Ordner. Es wird vorerst der System-Proxy verwendet (--system-proxy)",
	"proxy.errAdmin":                  "der transparente Modus erfordert die Ausführung als Administrator",

	"wc.usage": `httpsniff winconfig — AppContainer-Loopback-Ausnahmen (Fiddlers WinConfig-Äquivalent)

Befehle:
  list                alle AppContainer und ihren Ausnahmestatus anzeigen
  exempt-all          Loopback für ALLE Apps erlauben (Exempt All)
  exempt <string>     Loopback für Apps erlauben, deren Name/Paket <string> enthält
  clear               alle Loopback-Ausnahmen entfernen

Erfordert Administratorrechte (außer list).
`,
	"wc.needSubstr":    "geben Sie einen Namen-/Paket-Teilstring der App an: httpsniff winconfig exempt <string>",
	"wc.error":         "Fehler:",
	"wc.enumErr":       "NetworkIsolationEnumAppContainers gab Code %d zurück",
	"wc.found":         "AppContainer gefunden: %d (✓ = Loopback erlaubt)",
	"wc.exemptCount":   "Aktuelle Ausnahmen: %d",
	"wc.exemptAllDone": "✓ Exempt All: Loopback für %d Apps erlaubt.",
	"wc.noMatch":       "Keine Apps für \"%s\" gefunden.",
	"wc.exemptDone":    "Fertig: %d hinzugefügt, %d Ausnahmen insgesamt.",
	"wc.cleared":       "Alle Loopback-Ausnahmen entfernt.",
	"wc.setErr":        "NetworkIsolationSetAppContainerConfig gab Code %d zurück ",
	"wc.setErrDenied":  "(Zugriff verweigert — als Administrator ausführen)",
	"wc.needAdmin":     "⚠ Administratorrechte erforderlich. Starten Sie die Konsole „als Administrator“.",

	"up.needPid":    "geben Sie --pid <PID> der Flutter-App an",
	"up.needAdmin":  "⚠ Administratorrechte erforderlich, um in den Prozessspeicher zu schreiben.",
	"up.sigErr":     "Signaturfehler:",
	"up.moduleErr":  "flutter_windows.dll im Prozess %d nicht gefunden: %v",
	"up.moduleInfo": "flutter_windows.dll: Basis=0x%X Größe=%d",
	"up.openErr":    "OpenProcess: %v",
	"up.matches":    "Signaturtreffer: %d",
	"up.correcting": "Funktion bereits von einer älteren (Rückgabe 0) Version gepatcht — korrigiere auf Erfolg (1)",
	"up.notFound":   "Prüffunktion nicht gefunden — evtl. andere Flutter-Version (eigene --sig angeben)",
	"up.multiple":   "mehrere Treffer — aus Vorsicht kein Patch. Präzisieren Sie die Signatur (--sig).",
	"up.funcAddr":   "Zertifikatsprüffunktion: 0x%X",
	"up.dryRun":     "(dry-run) fügen Sie --apply hinzu, um den Patch anzuwenden",
	"up.patchErr":   "Patch fehlgeschlagen: %v",
	"up.patchOK":    "✓ TLS-Prüfung deaktiviert. Starten Sie jetzt die Erfassung mit --tls-mitm.",
	"up.flagPid":    "PID der Flutter-App",
	"up.flagApply":  "Patch anwenden (ohne Flag — nur Suche/dry-run)",
	"up.flagSig":    "Signatur der Prüffunktion (hex, ?? — Maske)",
	"up.flagAuto":   "Automatischer Modus: alle bekannten Signaturen ausprobieren und anwenden",
	"up.flagDump":   "Funktionsbytes vor/nach Patch anzeigen (Diagnose)",

	"up.autoStart":        "Automatischer Modus: Teste bekannte Flutter/BoringSSL-Signaturen…",
	"up.autoAlreadyPatched": "Funktion bereits von älterer Version gepatcht (Rückgabe 0) — korrigiere auf Rückgabe 1",
	"up.autoFound":        "✓ Signatur gefunden: %s — %s",
	"up.autoNotFound":     "keine bekannte Signatur passt — evtl. sehr neue Flutter-Version (geben Sie eigene --sig an)",
	"up.autoDryRun":       "(dry-run) fügen Sie --apply hinzu, um den Patch anzuwenden",
}
