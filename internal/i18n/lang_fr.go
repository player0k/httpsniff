package i18n

// fr — французский каталог.
var fr = map[string]string{
	"flag.port":            "port d'écoute du proxy",
	"flag.addr":            "adresse (hôte) d'écoute du proxy",
	"flag.pid":             "capturer uniquement le trafic du processus avec ce PID (0 = tous les processus)",
	"flag.caCert":          "chemin du certificat CA (le vôtre ou généré)",
	"flag.caKey":           "chemin de la clé privée du CA",
	"flag.maxBody":         "nombre max d'octets du corps à afficher (0 = illimité)",
	"flag.insecure":        "ne pas vérifier les certificats des serveurs amont",
	"flag.systemProxy":     "activer automatiquement le proxy système (capture clé en main)",
	"flag.transparent":     "capture transparente (WinDivert sous Windows / iptables sous Linux / pf sous macOS)",
	"flag.quic":            "capture HTTP/3 (QUIC/UDP) — nécessite le mode transparent",
	"flag.transparentPort": "port de capture TCP transparente",
	"flag.quicPort":        "port UDP de capture QUIC",
	"flag.logFile":         "dupliquer la capture dans un fichier (sans couleurs ANSI)",
	"flag.noTUI":           "désactiver le TUI, afficher le journal en flux",
	"flag.tlsMITM":         "en mode transparent, déchiffrer HTTPS (MITM) ; sinon uniquement hôte SNI + relais",
	"flag.lang":            "langue de l'interface : en, ru, fr, de, nl, es, pt (par défaut : système)",

	"main.errCAInit":       "Erreur d'initialisation du CA : %v",
	"main.errLogOpen":      "Impossible d'ouvrir le fichier journal : %v",
	"main.errProxy":        "Erreur du proxy : %v",
	"main.warnSysProxy":    "⚠ Impossible d'activer le proxy système : %v",
	"main.warnTransparent": "⚠ Mode transparent indisponible : %v",
	"main.warnQUIC":        "⚠ Capture QUIC indisponible : %v",
	"main.shutdown":        "Arrêt, restauration des paramètres…",
	"main.restored":        "Paramètres du proxy système restaurés.",

	"usage.header": `httpsniff — intercepteur de trafic HTTP/HTTPS (proxy MITM) pour Windows, Linux et macOS

Utilisation :
  httpsniff [options]
  httpsniff winconfig <list|exempt-all|exempt CHAÎNE|clear>   (Windows uniquement)
  httpsniff unpin --pid <PID> [--apply|--auto]   désactiver la vérification TLS d'une app Flutter
  httpsniff restore                         restaurer les paramètres du proxy après un plantage

Capture clé en main (sans configuration manuelle du proxy dans le client) :
  httpsniff                       # le proxy système est activé automatiquement
  httpsniff --transparent         # + capture transparente (WinDivert/iptables, admin requis)
  httpsniff --quic                # + capture HTTP/3 (QUIC), implique --transparent

Options :
`,
	"usage.footer": `
Comment utiliser :
  1. Lancez httpsniff — au premier lancement un CA est généré (ca-cert.pem).
  2. Installez ca-cert.pem dans les autorités de certification racine de confiance de l'OS/navigateur.
  3. Le trafic passe automatiquement par l'intercepteur (proxy système). Pour les applis qui
     ignorent le proxy système, ajoutez --transparent (droits administrateur requis).
  4. (Facultatif) Limitez la capture à un seul processus via --pid <PID>.

Windows 11 — accès des applis AppContainer (UWP/WinUI/Store) au proxy :
  httpsniff winconfig exempt-all   # autoriser le loopback pour toutes (équivalent WinConfig de Fiddler)

`,

	"banner.title":           "httpsniff — interception du trafic HTTP/HTTPS/2/3",
	"banner.platform":        "Plateforme",
	"banner.proxy":           "Proxy",
	"banner.pidFilter":       "Filtre PID",
	"banner.pidNone":         "(aucun — capture de tous les processus)",
	"banner.caCert":          "Cert. CA",
	"banner.protocols":       "Protocoles",
	"banner.mode":            "Mode",
	"banner.logFile":         "Fichier journal",
	"banner.modeSystem":      "proxy système",
	"banner.modeExplicit":    "proxy explicite",
	"banner.modeTransparent": " + transparent",
	"banner.caWarn":          "⚠ Un nouveau CA a été généré. Installez-le dans les autorités de\n    certification racine de confiance, sinon les clients HTTPS signaleront le certificat.",
	"banner.installWin":      "Windows : certutil -addstore -f \"ROOT\" %s",
	"banner.installLinux":    "Linux (Debian/Ubuntu) : sudo cp %s /usr/local/share/ca-certificates/httpsniff.crt && sudo update-ca-certificates",
	"banner.installMacOS":    "macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s",
	"banner.hotkeys":         "Raccourcis : p — définir le PID, a — tous les processus, s — statut, q/Ctrl+C — quitter.",

	"log.request":        "REQUÊTE",
	"log.response":       "RÉPONSE",
	"log.requestBody":    "corps de la requête",
	"log.responseBody":   "corps de la réponse",
	"log.bytes":          "octets",
	"log.decoded":        "décodé : %s",
	"log.binary":         "[données binaires, %d octets, non affichées]",
	"log.truncated":      "… tronqué (%d sur %d octets)",
	"log.error":          "erreur : %v",
	"log.httpsNoDecrypt": "(non déchiffré)",
	"log.httpsNote":      "corps chiffré ; seul l'hôte (SNI) est affiché. Le déchiffrement exige que l'appli fasse confiance à notre CA.",
	"log.mitmRejected":   "MITM TLS refusé par l'appli pour %s — certificat non approuvé (lancez `unpin`) ; bascule en pass-through pour cet hôte",

	"ui.status":         "Filtre : %s   [p] définir PID   [a] tous   [s] statut   [q] quitter",
	"ui.filterAll":      "tous les processus",
	"ui.filterPID":      "PID %d",
	"ui.logToFile":      "[écriture dans un fichier]",
	"ui.captureAll":     "Capture de tous les processus.",
	"ui.help":           "Raccourcis : p — PID, a — tous, s — statut, q — quitter",
	"ui.pidPrompt":      "PID (Entrée — tous les processus) : ",
	"ui.tuiLogTitle":    " httpsniff — journal (↑/↓, PgUp/PgDn, souris) ",
	"ui.tuiFilterTitle": " Filtrer par processus ",
	"ui.tuiPidLabel":    " PID (vide = tous) : ",
	"ui.tuiError":       "Erreur du TUI :",

	"sysproxy.hintWin":         "Proxy système Windows activé (WinINET). Les navigateurs et applis qui utilisent\n  les paramètres système passeront automatiquement par l'intercepteur.",
	"sysproxy.hintLinux":       "Proxy système GNOME activé (gsettings). Pour capturer hors de GNOME,\n  utilisez --transparent (iptables REDIRECT).",
	"sysproxy.hintMacOS":       "Proxy système macOS activé (networksetup) sur tous les services réseau actifs.\n  Les apps qui respectent le proxy système passent automatiquement par l'intercepteur.",
	"sysproxy.errNetworksetup": "networksetup introuvable ; configurez le proxy manuellement dans Réglages Système › Réseau",
	"sysproxy.errNoServices":   "aucun service réseau actif trouvé (networksetup)",
	"sysproxy.errGsettings":    "gsettings introuvable ; utilisez --transparent ou configurez le proxy manuellement",
	"sysproxy.errUnsupported":  "la configuration automatique du proxy système n'est pas prise en charge sur cette plateforme",

	"proxy.quicListen":                "  MITM QUIC/HTTP-3 à l'écoute sur udp 127.0.0.1:%d (nécessite une redirection UDP:443 vers ce port)",
	"proxy.transparentWin":            "  Capture transparente via WinDivert active (TCP 80/443 → :%d)",
	"proxy.transparentLinux":          "  TCP transparent à l'écoute sur %s. Configurez la redirection, par ex. :\n    sudo iptables -t nat -A OUTPUT -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports %d",
	"proxy.transparentLinuxActive":    "  TCP transparent à l'écoute sur %s. iptables REDIRECT configuré automatiquement (TCP 80/443 → :%d). Les règles seront supprimées à la sortie.",
	"proxy.errIptablesNotFound":       "iptables introuvable ; installez iptables ou configurez la redirection manuellement",
	"proxy.errIptablesSetup":          "échec de la configuration de iptables REDIRECT : %s",
	"proxy.transparentMacOS":          "  TCP transparent à l'écoute sur %s. Configurez la redirection pf, par ex. :\n    echo 'rdr pass on lo0 inet proto tcp to any port {80,443} -> 127.0.0.1 port %d' | sudo pfctl -ef -",
	"proxy.errPfOpen":                 "impossible d'ouvrir /dev/pf (le mode transparent requiert root)",
	"proxy.errTransparentUnsupported": "le mode transparent n'est pas pris en charge sur cette plateforme",
	"proxy.errWinDivertMissing":       "WinDivert.dll introuvable à côté du programme ; téléchargez WinDivert (https://reqrypt.org/windivert.html), placez WinDivert.dll et WinDivert64.sys dans le dossier de httpsniff. Repli sur le proxy système (--system-proxy)",
	"proxy.errAdmin":                  "le mode transparent nécessite une exécution en tant qu'administrateur",

	"wc.usage": `httpsniff winconfig — exemptions loopback AppContainer (équivalent WinConfig de Fiddler)

Commandes :
  list                afficher tous les AppContainers et leur statut d'exemption
  exempt-all          autoriser le loopback pour TOUTES les applis (Exempt All)
  exempt <chaîne>     autoriser le loopback pour les applis dont le nom/paquet contient <chaîne>
  clear               supprimer toutes les exemptions loopback

Nécessite des droits administrateur (sauf list).
`,
	"wc.needSubstr":    "indiquez une sous-chaîne du nom/paquet de l'appli : httpsniff winconfig exempt <chaîne>",
	"wc.error":         "Erreur :",
	"wc.enumErr":       "NetworkIsolationEnumAppContainers a renvoyé le code %d",
	"wc.found":         "AppContainers trouvés : %d (✓ = loopback autorisé)",
	"wc.exemptCount":   "Exemptions actuelles : %d",
	"wc.exemptAllDone": "✓ Exempt All : loopback autorisé pour %d applis.",
	"wc.noMatch":       "Aucune appli trouvée pour « %s ».",
	"wc.exemptDone":    "Terminé : %d ajoutées, %d exemptions au total.",
	"wc.cleared":       "Toutes les exemptions loopback supprimées.",
	"wc.setErr":        "NetworkIsolationSetAppContainerConfig a renvoyé le code %d ",
	"wc.setErrDenied":  "(accès refusé — exécutez en tant qu'administrateur)",
	"wc.needAdmin":     "⚠ Droits administrateur requis. Lancez la console « en tant qu'administrateur ».",

	"up.needPid":    "indiquez --pid <PID> de l'appli Flutter",
	"up.needAdmin":  "⚠ Droits administrateur requis pour écrire dans la mémoire du processus.",
	"up.sigErr":     "erreur de signature :",
	"up.moduleErr":  "flutter_windows.dll introuvable dans le processus %d : %v",
	"up.moduleInfo": "flutter_windows.dll : base=0x%X taille=%d",
	"up.openErr":    "OpenProcess : %v",
	"up.matches":    "correspondances de signature : %d",
	"up.correcting": "fonction déjà patchée par une ancienne version (retour 0) — correction en succès (1)",
	"up.notFound":   "fonction de vérification introuvable — peut-être une autre version de Flutter (définissez votre propre --sig)",
	"up.multiple":   "plusieurs correspondances — patch annulé par précaution. Affinez la signature (--sig).",
	"up.funcAddr":   "fonction de vérification du certificat : 0x%X",
	"up.dryRun":     "(dry-run) ajoutez --apply pour appliquer le patch",
	"up.patchErr":   "échec du patch : %v",
	"up.patchOK":    "✓ Vérification TLS désactivée. Lancez maintenant la capture avec --tls-mitm.",
	"up.flagPid":    "PID de l'appli Flutter",
	"up.flagApply":  "appliquer le patch (sans l'option — recherche/dry-run uniquement)",
	"up.flagSig":    "signature de la fonction de vérification (hex, ?? — masque)",
	"up.flagAuto":   "mode automatique : essayer toutes les signatures connues et appliquer",
	"up.flagDump":   "afficher les octets de la fonction avant/après le patch (diagnostic)",

	"up.autoStart":        "Mode automatique : test des signatures Flutter/BoringSSL connues…",
	"up.autoAlreadyPatched": "fonction déjà patchée par une version antérieure (retour 0) — correction en retour 1",
	"up.autoFound":        "✓ Signature trouvée : %s — %s",
	"up.autoNotFound":     "aucune signature connue ne correspond — peut-être une version très récente de Flutter (définissez votre propre --sig)",
	"up.autoDryRun":       "(dry-run) ajoutez --apply pour appliquer le patch",
}
