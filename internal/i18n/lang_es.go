package i18n

// es — испанский каталог.
var es = map[string]string{
	"flag.port":            "puerto de escucha del proxy",
	"flag.addr":            "dirección (host) de escucha del proxy",
	"flag.pid":             "capturar solo el tráfico del proceso con este PID (0 = todos los procesos)",
	"flag.caCert":          "ruta al certificado CA (propio o generado)",
	"flag.caKey":           "ruta a la clave privada del CA",
	"flag.maxBody":         "máximo de bytes del cuerpo a mostrar (0 = sin límite)",
	"flag.insecure":        "no verificar los certificados de los servidores upstream",
	"flag.systemProxy":     "activar automáticamente el proxy del sistema (captura lista para usar)",
	"flag.transparent":     "captura transparente (WinDivert en Windows / iptables en Linux / pf en macOS)",
	"flag.quic":            "capturar HTTP/3 (QUIC/UDP) — requiere modo transparente",
	"flag.transparentPort": "puerto de captura TCP transparente",
	"flag.quicPort":        "puerto UDP de captura QUIC",
	"flag.logFile":         "duplicar la captura en un archivo (sin colores ANSI)",
	"flag.noTUI":           "desactivar la TUI, mostrar el registro en flujo",
	"flag.tlsMITM":         "en modo transparente, descifrar HTTPS (MITM); si no, solo host SNI + reenvío",
	"flag.lang":            "idioma de la interfaz: en, ru, fr, de, nl, es, pt (por defecto: sistema)",

	"main.errCAInit":       "Error de inicialización del CA: %v",
	"main.errLogOpen":      "No se pudo abrir el archivo de registro: %v",
	"main.errProxy":        "Error del proxy: %v",
	"main.warnSysProxy":    "⚠ No se pudo activar el proxy del sistema: %v",
	"main.warnTransparent": "⚠ Modo transparente no disponible: %v",
	"main.warnQUIC":        "⚠ Captura QUIC no disponible: %v",
	"main.shutdown":        "Cerrando, restaurando la configuración…",
	"main.restored":        "Configuración del proxy del sistema restaurada.",

	"usage.header": `httpsniff — interceptor de tráfico HTTP/HTTPS (proxy MITM) para Windows, Linux y macOS

Uso:
  httpsniff [opciones]
  httpsniff winconfig <list|exempt-all|exempt CADENA|clear>   (solo Windows)
  httpsniff unpin --pid <PID> [--apply|--auto]   desactivar la verificación TLS de una app Flutter
  httpsniff restore                         restaurar la configuración del proxy tras un fallo

Captura lista para usar (sin configurar el proxy manualmente en el cliente):
  httpsniff                       # el proxy del sistema se activa automáticamente
  httpsniff --transparent         # + captura transparente (WinDivert/iptables, requiere admin)
  httpsniff --quic                # + captura HTTP/3 (QUIC), implica --transparent

Opciones:
`,
	"usage.footer": `
Cómo usar:
  1. Ejecute httpsniff — en el primer arranque se genera un CA (ca-cert.pem).
  2. Instale ca-cert.pem en las autoridades de certificación raíz de confianza del SO/navegador.
  3. El tráfico pasa automáticamente por el interceptor (proxy del sistema). Para apps que
     ignoran el proxy del sistema, añada --transparent (requiere permisos de administrador).
  4. (Opcional) Limite la captura a un solo proceso con --pid <PID>.

Windows 11 — acceso de apps AppContainer (UWP/WinUI/Store) al proxy:
  httpsniff winconfig exempt-all   # permitir loopback a todas (equivalente a WinConfig de Fiddler)

`,

	"banner.title":           "httpsniff — interceptación de tráfico HTTP/HTTPS/2/3",
	"banner.platform":        "Plataforma",
	"banner.proxy":           "Proxy",
	"banner.pidFilter":       "Filtro PID",
	"banner.pidNone":         "(ninguno — capturando todos los procesos)",
	"banner.caCert":          "Cert. CA",
	"banner.protocols":       "Protocolos",
	"banner.mode":            "Modo",
	"banner.logFile":         "Archivo de registro",
	"banner.modeSystem":      "proxy del sistema",
	"banner.modeExplicit":    "proxy explícito",
	"banner.modeTransparent": " + transparente",
	"banner.caWarn":          "⚠ Se generó un nuevo CA. Instálelo en las autoridades de certificación\n    raíz de confianza, o los clientes HTTPS se quejarán del certificado.",
	"banner.installWin":      "Windows: certutil -addstore -f \"ROOT\" %s",
	"banner.installLinux":    "Linux (Debian/Ubuntu): sudo cp %s /usr/local/share/ca-certificates/httpsniff.crt && sudo update-ca-certificates",
	"banner.installMacOS":    "macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s",
	"banner.hotkeys":         "Atajos: p — fijar PID, a — todos los procesos, s — estado, q/Ctrl+C — salir.",

	"log.request":        "PETICIÓN",
	"log.response":       "RESPUESTA",
	"log.requestBody":    "cuerpo de la petición",
	"log.responseBody":   "cuerpo de la respuesta",
	"log.bytes":          "bytes",
	"log.decoded":        "decodificado: %s",
	"log.binary":         "[datos binarios, %d bytes, no mostrados]",
	"log.truncated":      "… truncado (%d de %d bytes)",
	"log.error":          "error: %v",
	"log.httpsNoDecrypt": "(sin descifrar)",
	"log.httpsNote":      "cuerpo cifrado; solo se muestra el host (SNI). El descifrado requiere que la app confíe en nuestro CA.",
	"log.mitmRejected":   "MITM TLS rechazado por la app para %s — certificado no confiable (ejecuta `unpin`); se usa passthrough para este host",

	"ui.status":         "Filtro: %s   [p] fijar PID   [a] todos   [s] estado   [q] salir",
	"ui.filterAll":      "todos los procesos",
	"ui.filterPID":      "PID %d",
	"ui.logToFile":      "[escribiendo en archivo]",
	"ui.captureAll":     "Capturando todos los procesos.",
	"ui.help":           "Atajos: p — PID, a — todos, s — estado, q — salir",
	"ui.pidPrompt":      "PID (Enter — todos los procesos): ",
	"ui.tuiLogTitle":    " httpsniff — registro (↑/↓, RePág/AvPág, ratón) ",
	"ui.tuiFilterTitle": " Filtrar por proceso ",
	"ui.tuiPidLabel":    " PID (vacío = todos): ",
	"ui.tuiError":       "Error de la TUI:",

	"sysproxy.hintWin":         "Proxy del sistema de Windows activado (WinINET). Los navegadores y apps que usan\n  la configuración del sistema pasarán por el interceptor automáticamente.",
	"sysproxy.hintLinux":       "Proxy del sistema de GNOME activado (gsettings). Para capturar fuera de GNOME\n  use --transparent (iptables REDIRECT).",
	"sysproxy.hintMacOS":       "Proxy del sistema de macOS activado (networksetup) en todos los servicios de red activos.\n  Las apps que respetan el proxy del sistema pasan por el interceptor automáticamente.",
	"sysproxy.errNetworksetup": "networksetup no encontrado; configure el proxy manualmente en Ajustes del Sistema › Red",
	"sysproxy.errNoServices":   "no se encontraron servicios de red activos (networksetup)",
	"sysproxy.errGsettings":    "gsettings no encontrado; use --transparent o configure el proxy manualmente",
	"sysproxy.errUnsupported":  "la configuración automática del proxy del sistema no es compatible con esta plataforma",

	"proxy.quicListen":                "  MITM QUIC/HTTP-3 escuchando en udp 127.0.0.1:%d (requiere redirección UDP:443 a este puerto)",
	"proxy.transparentWin":            "  Captura transparente vía WinDivert activa (TCP 80/443 → :%d)",
	"proxy.transparentLinux":          "  TCP transparente escuchando en %s. Configure la redirección, p. ej.:\n    sudo iptables -t nat -A OUTPUT -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports %d",
	"proxy.transparentLinuxActive":    "  TCP transparente escuchando en %s. iptables REDIRECT configurado automáticamente (TCP 80/443 → :%d). Las reglas se eliminarán al salir.",
	"proxy.errIptablesNotFound":       "iptables no encontrado; instale iptables o configure la redirección manualmente",
	"proxy.errIptablesSetup":          "error al configurar iptables REDIRECT: %s",
	"proxy.transparentMacOS":          "  TCP transparente escuchando en %s. Configure la redirección de pf, p. ej.:\n    echo 'rdr pass on lo0 inet proto tcp to any port {80,443} -> 127.0.0.1 port %d' | sudo pfctl -ef -",
	"proxy.errPfOpen":                 "no se puede abrir /dev/pf (el modo transparente requiere root)",
	"proxy.errTransparentUnsupported": "el modo transparente no es compatible con esta plataforma",
	"proxy.errWinDivertMissing":       "WinDivert.dll no encontrado junto al programa; descargue WinDivert (https://reqrypt.org/windivert.html), coloque WinDivert.dll y WinDivert64.sys en la carpeta de httpsniff. Por ahora se usa el proxy del sistema (--system-proxy)",
	"proxy.errAdmin":                  "el modo transparente requiere ejecutarse como administrador",

	"wc.usage": `httpsniff winconfig — exenciones de loopback de AppContainer (equivalente a WinConfig de Fiddler)

Comandos:
  list                mostrar todos los AppContainer y su estado de exención
  exempt-all          permitir loopback a TODAS las apps (Exempt All)
  exempt <cadena>     permitir loopback a las apps cuyo nombre/paquete contenga <cadena>
  clear               eliminar todas las exenciones de loopback

Requiere permisos de administrador (excepto list).
`,
	"wc.needSubstr":    "indique una subcadena del nombre/paquete de la app: httpsniff winconfig exempt <cadena>",
	"wc.error":         "Error:",
	"wc.enumErr":       "NetworkIsolationEnumAppContainers devolvió el código %d",
	"wc.found":         "AppContainer encontrados: %d (✓ = loopback permitido)",
	"wc.exemptCount":   "Exenciones actuales: %d",
	"wc.exemptAllDone": "✓ Exempt All: loopback permitido para %d apps.",
	"wc.noMatch":       "No se encontraron apps para \"%s\".",
	"wc.exemptDone":    "Listo: %d añadidas, %d exenciones en total.",
	"wc.cleared":       "Todas las exenciones de loopback eliminadas.",
	"wc.setErr":        "NetworkIsolationSetAppContainerConfig devolvió el código %d ",
	"wc.setErrDenied":  "(acceso denegado — ejecute como administrador)",
	"wc.needAdmin":     "⚠ Se requieren permisos de administrador. Inicie la consola «como administrador».",

	"up.needPid":    "indique --pid <PID> de la app Flutter",
	"up.needAdmin":  "⚠ Se requieren permisos de administrador para escribir en la memoria del proceso.",
	"up.sigErr":     "error de firma:",
	"up.moduleErr":  "flutter_windows.dll no encontrado en el proceso %d: %v",
	"up.moduleInfo": "flutter_windows.dll: base=0x%X tamaño=%d",
	"up.openErr":    "OpenProcess: %v",
	"up.matches":    "coincidencias de firma: %d",
	"up.correcting": "la función ya fue parcheada por una versión anterior (retorno 0) — corrigiendo a éxito (1)",
	"up.notFound":   "función de verificación no encontrada — quizá otra versión de Flutter (indique su propia --sig)",
	"up.multiple":   "varias coincidencias — no se parchea por precaución. Precise la firma (--sig).",
	"up.funcAddr":   "función de verificación del certificado: 0x%X",
	"up.dryRun":     "(dry-run) añada --apply para aplicar el parche",
	"up.patchErr":   "el parche falló: %v",
	"up.patchOK":    "✓ Verificación TLS desactivada. Ahora inicie la captura con --tls-mitm.",
	"up.flagPid":    "PID de la app Flutter",
	"up.flagApply":  "aplicar el parche (sin la opción — solo búsqueda/dry-run)",
	"up.flagSig":    "firma de la función de verificación (hex, ?? — máscara)",
	"up.flagAuto":   "modo automático: probar todas las firmas conocidas y aplicar",
	"up.flagDump":   "mostrar bytes de la función antes/después del parche (diagnóstico)",

	"up.autoStart":        "Modo automático: probando firmas conocidas de Flutter/BoringSSL…",
	"up.autoAlreadyPatched": "función ya parcheada por versión anterior (retorna 0) — corrigiendo a retorno 1",
	"up.autoFound":        "✓ Firma encontrada: %s — %s",
	"up.autoNotFound":     "ninguna firma conocida coincide — quizá versión muy nueva de Flutter (indique su propia --sig)",
	"up.autoDryRun":       "(dry-run) añada --apply para aplicar el parche",
}
