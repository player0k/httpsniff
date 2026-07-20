package i18n

// nl — нидерландский каталог.
var nl = map[string]string{
	"flag.port":            "luisterpoort van de proxy",
	"flag.addr":            "luisteradres (host) van de proxy",
	"flag.pid":             "alleen verkeer van het proces met deze PID onderscheppen (0 = alle processen)",
	"flag.caCert":          "pad naar het CA-certificaat (eigen of gegenereerd)",
	"flag.caKey":           "pad naar de privésleutel van de CA",
	"flag.maxBody":         "max. aantal body-bytes om te tonen (0 = onbeperkt)",
	"flag.insecure":        "certificaten van upstream-servers niet verifiëren",
	"flag.systemProxy":     "de systeemproxy automatisch inschakelen (onderscheppen out of the box)",
	"flag.transparent":     "transparant onderscheppen (WinDivert op Windows / iptables op Linux / pf op macOS)",
	"flag.quic":            "HTTP/3 (QUIC/UDP) onderscheppen — vereist transparante modus",
	"flag.transparentPort": "poort voor transparant TCP-onderscheppen",
	"flag.quicPort":        "UDP-poort voor QUIC-onderscheppen",
	"flag.logFile":         "onderschepping ook naar een bestand schrijven (zonder ANSI-kleuren)",
	"flag.noTUI":           "de TUI uitschakelen, log als stream tonen",
	"flag.tlsMITM":         "in transparante modus HTTPS ontsleutelen (MITM); anders alleen SNI-host + doorsturen",
	"flag.autoUnpin":       "met --tls-mitm: TLS-verificatie van nieuwe Flutter-processen auto uitschakelen (alleen Windows; standaard aan)",
	"flag.lang":            "interfacetaal: en, ru, fr, de, nl, es, pt (standaard: systeem)",

	"main.errCAInit":       "Fout bij initialiseren van CA: %v",
	"main.errLogOpen":      "Kon logbestand niet openen: %v",
	"main.errProxy":        "Proxyfout: %v",
	"main.warnSysProxy":    "⚠ Kon de systeemproxy niet inschakelen: %v",
	"main.warnTransparent": "⚠ Transparante modus niet beschikbaar: %v",
	"main.warnQUIC":        "⚠ QUIC-onderscheppen niet beschikbaar: %v",
	"main.shutdown":        "Afsluiten, instellingen worden hersteld…",
	"main.restored":        "Systeemproxy-instellingen hersteld.",
	"main.autoUnpinOn":     "auto-unpin: nieuwe Flutter-processen worden bewaakt (Windows)",

	"usage.header": `httpsniff — HTTP/HTTPS-verkeersonderschepper (MITM-proxy) voor Windows, Linux en macOS

Gebruik:
  httpsniff [opties]
  httpsniff winconfig <list|exempt-all|exempt TEKST|clear>   (alleen Windows)
  httpsniff unpin --pid <PID> [--apply|--auto]   TLS-verificatie van een Flutter-app uitschakelen
  httpsniff restore                         proxy-instellingen herstellen na een crash

Onderscheppen out of the box (geen handmatige proxyconfiguratie in de client):
  httpsniff                       # de systeemproxy wordt automatisch ingeschakeld
  httpsniff --transparent         # + transparant onderscheppen (WinDivert/iptables, admin nodig)
  httpsniff --quic                # + HTTP/3-(QUIC)-onderscheppen, impliceert --transparent

Opties:
`,
	"usage.footer": `
Gebruik:
  1. Start httpsniff — bij de eerste start wordt een CA gegenereerd (ca-cert.pem).
  2. Installeer ca-cert.pem in de vertrouwde hoofdcertificeringsinstanties van het OS/de browser.
  3. Verkeer loopt automatisch via de onderschepper (systeemproxy). Voor apps die de
     systeemproxy negeren, voeg --transparent toe (beheerdersrechten vereist).
  4. (Optioneel) Beperk het onderscheppen tot één proces met --pid <PID>.

Windows 11 — toegang van AppContainer-apps (UWP/WinUI/Store) tot de proxy:
  httpsniff winconfig exempt-all   # loopback voor alle toestaan (equivalent van Fiddlers WinConfig)

`,

	"banner.title":           "httpsniff — onderschepping van HTTP/HTTPS/2/3-verkeer",
	"banner.platform":        "Platform",
	"banner.proxy":           "Proxy",
	"banner.pidFilter":       "PID-filter",
	"banner.pidNone":         "(geen — alle processen worden onderschept)",
	"banner.caCert":          "CA-cert.",
	"banner.protocols":       "Protocollen",
	"banner.mode":            "Modus",
	"banner.logFile":         "Logbestand",
	"banner.modeSystem":      "systeemproxy",
	"banner.modeExplicit":    "expliciete proxy",
	"banner.modeTransparent": " + transparant",
	"banner.caWarn":          "⚠ Er is een nieuwe CA gegenereerd. Installeer deze in de vertrouwde\n    hoofdcertificeringsinstanties, anders klagen HTTPS-clients over het certificaat.",
	"banner.installWin":      "Windows: certutil -addstore -f \"ROOT\" %s",
	"banner.installLinux":    "Linux (Debian/Ubuntu): sudo cp %s /usr/local/share/ca-certificates/httpsniff.crt && sudo update-ca-certificates",
	"banner.installMacOS":    "macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s",
	"banner.hotkeys":         "Sneltoetsen: p — PID instellen, a — alle processen, s — status, q/Ctrl+C — afsluiten.",

	"log.request":        "VERZOEK",
	"log.response":       "ANTWOORD",
	"log.requestBody":    "verzoek-body",
	"log.responseBody":   "antwoord-body",
	"log.bytes":          "bytes",
	"log.decoded":        "gedecodeerd: %s",
	"log.binary":         "[binaire gegevens, %d bytes, niet getoond]",
	"log.truncated":      "… afgekapt (%d van %d bytes)",
	"log.error":          "fout: %v",
	"log.httpsNoDecrypt": "(niet ontsleuteld)",
	"log.httpsNote":      "body is versleuteld; alleen de host (SNI) wordt getoond. Ontsleuteling vereist dat de app onze CA vertrouwt.",
	"log.mitmRejected":   "TLS-MITM geweigerd door app voor %s — certificaat niet vertrouwd; terugval naar pass-through voor deze host",
	"log.mitmHintCA":     "pid %d is geen Flutter — de CA moet vertrouwd zijn (curl/browsers gebruiken de systeemstore)",

	"ui.status":         "Filter: %s   [p] PID instellen   [a] alle   [s] status   [q] afsluiten",
	"ui.filterAll":      "alle processen",
	"ui.filterPID":      "PID %d",
	"ui.logToFile":      "[naar bestand schrijven]",
	"ui.captureAll":     "Alle processen worden onderschept.",
	"ui.help":           "Sneltoetsen: p — PID, a — alle, s — status, q — afsluiten",
	"ui.pidPrompt":      "PID (Enter — alle processen): ",
	"ui.tuiLogTitle":    " httpsniff — log (↑/↓, PgUp/PgDn, muis) ",
	"ui.tuiFilterTitle": " Filteren op proces ",
	"ui.tuiPidLabel":    " PID (leeg = alle): ",
	"ui.tuiError":       "TUI-fout:",

	"sysproxy.hintWin":         "Windows-systeemproxy ingeschakeld (WinINET). Browsers en apps die de\n  systeeminstellingen gebruiken, lopen automatisch via de onderschepper.",
	"sysproxy.hintLinux":       "GNOME-systeemproxy ingeschakeld (gsettings). Om buiten GNOME te onderscheppen,\n  gebruik --transparent (iptables REDIRECT).",
	"sysproxy.hintMacOS":       "macOS-systeemproxy ingeschakeld (networksetup) op alle actieve netwerkdiensten.\n  Apps die de systeemproxy respecteren, gaan automatisch via de onderschepper.",
	"sysproxy.errNetworksetup": "networksetup niet gevonden; stel de proxy handmatig in via Systeeminstellingen › Netwerk",
	"sysproxy.errNoServices":   "geen actieve netwerkdiensten gevonden (networksetup)",
	"sysproxy.errGsettings":    "gsettings niet gevonden; gebruik --transparent of stel de proxy handmatig in",
	"sysproxy.errUnsupported":  "automatische systeemproxy-instelling wordt niet ondersteund op dit platform",

	"proxy.quicListen":                "  QUIC/HTTP-3-MITM luistert op udp 127.0.0.1:%d (vereist UDP:443-omleiding naar deze poort)",
	"proxy.transparentWin":            "  Transparant onderscheppen via WinDivert actief (TCP 80/443 → :%d)",
	"proxy.transparentLinux":          "  Transparant TCP luistert op %s. Configureer omleiding, bijv.:\n    sudo iptables -t nat -A OUTPUT -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports %d",
	"proxy.transparentLinuxActive":    "  Transparant TCP luistert op %s. iptables REDIRECT automatisch geconfigureerd (TCP 80/443 → :%d). Regels worden bij afsluiten verwijderd.",
	"proxy.errIptablesNotFound":       "iptables niet gevonden; installeer iptables of configureer omleiding handmatig",
	"proxy.errIptablesSetup":          "kan iptables REDIRECT niet instellen: %s",
	"proxy.transparentMacOS":          "  Transparant TCP luistert op %s. Configureer pf-omleiding, bijv.:\n    echo 'rdr pass on lo0 inet proto tcp to any port {80,443} -> 127.0.0.1 port %d' | sudo pfctl -ef -",
	"proxy.errPfOpen":                 "kan /dev/pf niet openen (transparante modus vereist root)",
	"proxy.errTransparentUnsupported": "de transparante modus wordt niet ondersteund op dit platform",
	"proxy.errWinDivertMissing":       "WinDivert.dll niet naast het programma gevonden; download WinDivert (https://reqrypt.org/windivert.html), plaats WinDivert.dll en WinDivert64.sys in de httpsniff-map. Voorlopig wordt de systeemproxy gebruikt (--system-proxy)",
	"proxy.errAdmin":                  "de transparante modus vereist uitvoeren als administrator",

	"wc.usage": `httpsniff winconfig — AppContainer-loopback-uitzonderingen (equivalent van Fiddlers WinConfig)

Commando's:
  list                alle AppContainers en hun uitzonderingsstatus tonen
  exempt-all          loopback voor ALLE apps toestaan (Exempt All)
  exempt <tekst>      loopback toestaan voor apps waarvan de naam/pakket <tekst> bevat
  clear               alle loopback-uitzonderingen verwijderen

Vereist beheerdersrechten (behalve list).
`,
	"wc.needSubstr":    "geef een naam-/pakket-deeltekst van de app op: httpsniff winconfig exempt <tekst>",
	"wc.error":         "Fout:",
	"wc.enumErr":       "NetworkIsolationEnumAppContainers gaf code %d terug",
	"wc.found":         "AppContainers gevonden: %d (✓ = loopback toegestaan)",
	"wc.exemptCount":   "Huidige uitzonderingen: %d",
	"wc.exemptAllDone": "✓ Exempt All: loopback toegestaan voor %d apps.",
	"wc.noMatch":       "Geen apps gevonden voor \"%s\".",
	"wc.exemptDone":    "Klaar: %d toegevoegd, %d uitzonderingen in totaal.",
	"wc.cleared":       "Alle loopback-uitzonderingen verwijderd.",
	"wc.setErr":        "NetworkIsolationSetAppContainerConfig gaf code %d terug ",
	"wc.setErrDenied":  "(toegang geweigerd — voer uit als administrator)",
	"wc.needAdmin":     "⚠ Beheerdersrechten vereist. Start de console „als administrator”.",

	"up.needPid":    "geef --pid <PID> van de Flutter-app op",
	"up.needAdmin":  "⚠ Beheerdersrechten vereist om naar het procesgeheugen te schrijven.",
	"up.sigErr":     "signatuurfout:",
	"up.moduleErr":  "flutter_windows.dll niet gevonden in proces %d: %v",
	"up.moduleInfo": "flutter_windows.dll: basis=0x%X grootte=%d",
	"up.openErr":    "OpenProcess: %v",
	"up.matches":    "signatuurtreffers: %d",
	"up.correcting": "functie al gepatcht door een oudere (retour 0) build — corrigeren naar succes (1)",
	"up.notFound":   "verificatiefunctie niet gevonden — mogelijk een andere Flutter-versie (geef eigen --sig op)",
	"up.multiple":   "meerdere treffers — uit voorzorg geen patch. Verfijn de signatuur (--sig).",
	"up.funcAddr":   "certificaatverificatiefunctie: 0x%X",
	"up.dryRun":     "(dry-run) voeg --apply toe om de patch toe te passen",
	"up.patchErr":   "patch mislukt: %v",
	"up.patchOK":    "✓ TLS-verificatie uitgeschakeld. Start nu het onderscheppen met --tls-mitm.",
	"up.flagPid":    "PID van de Flutter-app",
	"up.flagApply":  "de patch toepassen (zonder de vlag — alleen zoeken/dry-run)",
	"up.flagSig":    "signatuur van de verificatiefunctie (hex, ?? — masker)",
	"up.flagAuto":   "automatische modus: alle bekende signaturen proberen en toepassen",
	"up.flagDump":   "functie-bytes voor/na de patch weergeven (diagnose)",

	"up.autoStart":        "Automatische modus: bekende Flutter/BoringSSL.signaturen testen…",
	"up.autoAlreadyPatched": "functie al gepatcht door oudere versie (retourneert 0) — corrigeren naar retourneert 1",
	"up.autoFound":        "✓ Signatuur gevonden: %s — %s",
	"up.autoNotFound":     "geen bekende signatuur komt overeen — mogelijk een zeer nieuwe Flutter-versie (geef eigen --sig op)",
	"up.autoDryRun":       "(dry-run) voeg --apply toe om de patch toe te passen",
}
