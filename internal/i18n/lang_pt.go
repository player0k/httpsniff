package i18n

// pt — португальский каталог.
var pt = map[string]string{
	"flag.port":            "porta de escuta do proxy",
	"flag.addr":            "endereço (host) de escuta do proxy",
	"flag.pid":             "capturar apenas o tráfego do processo com este PID (0 = todos os processos)",
	"flag.caCert":          "caminho do certificado CA (próprio ou gerado)",
	"flag.caKey":           "caminho da chave privada do CA",
	"flag.maxBody":         "máximo de bytes do corpo a exibir (0 = sem limite)",
	"flag.insecure":        "não verificar os certificados dos servidores upstream",
	"flag.systemProxy":     "ativar automaticamente o proxy do sistema (captura pronta para uso)",
	"flag.transparent":     "captura transparente (WinDivert no Windows / iptables no Linux / pf no macOS)",
	"flag.quic":            "capturar HTTP/3 (QUIC/UDP) — requer o modo transparente",
	"flag.transparentPort": "porta de captura TCP transparente",
	"flag.quicPort":        "porta UDP de captura QUIC",
	"flag.logFile":         "duplicar a captura em um arquivo (sem cores ANSI)",
	"flag.noTUI":           "desativar a TUI, exibir o log em fluxo",
	"flag.tlsMITM":         "no modo transparente, descriptografar HTTPS (MITM); caso contrário, apenas host SNI + encaminhamento",
	"flag.autoUnpin":       "com --tls-mitm: desativar auto. a verificação TLS de novos processos Flutter (somente Windows; padrão ligado)",
	"flag.lang":            "idioma da interface: en, ru, fr, de, nl, es, pt (padrão: sistema)",

	"main.errCAInit":       "Erro de inicialização do CA: %v",
	"main.errLogOpen":      "Não foi possível abrir o arquivo de log: %v",
	"main.errProxy":        "Erro do proxy: %v",
	"main.warnSysProxy":    "⚠ Não foi possível ativar o proxy do sistema: %v",
	"main.warnTransparent": "⚠ Modo transparente indisponível: %v",
	"main.warnQUIC":        "⚠ Captura QUIC indisponível: %v",
	"main.shutdown":        "Encerrando, restaurando as configurações…",
	"main.restored":        "Configurações do proxy do sistema restauradas.",
	"main.autoUnpinOn":     "auto-unpin: monitorando novos processos Flutter (Windows)",

	"usage.header": `httpsniff — interceptador de tráfego HTTP/HTTPS (proxy MITM) para Windows, Linux e macOS

Uso:
  httpsniff [opções]
  httpsniff winconfig <list|exempt-all|exempt TEXTO|clear>   (apenas Windows)
  httpsniff unpin --pid <PID> [--apply|--auto]   desativar a verificação TLS de um app Flutter
  httpsniff restore                         restaurar as configurações do proxy após uma falha

Captura pronta para uso (sem configurar o proxy manualmente no cliente):
  httpsniff                       # o proxy do sistema é ativado automaticamente
  httpsniff --transparent         # + captura transparente (WinDivert/iptables, requer admin)
  httpsniff --quic                # + captura HTTP/3 (QUIC), implica --transparent

Opções:
`,
	"usage.footer": `
Como usar:
  1. Execute httpsniff — na primeira execução um CA é gerado (ca-cert.pem).
  2. Instale ca-cert.pem nas autoridades de certificação raiz confiáveis do SO/navegador.
  3. O tráfego passa automaticamente pelo interceptador (proxy do sistema). Para apps que
     ignoram o proxy do sistema, adicione --transparent (requer permissões de administrador).
  4. (Opcional) Limite a captura a um único processo com --pid <PID>.

Windows 11 — acesso de apps AppContainer (UWP/WinUI/Store) ao proxy:
  httpsniff winconfig exempt-all   # permitir loopback a todos (equivalente ao WinConfig do Fiddler)

`,

	"banner.title":           "httpsniff — interceptação de tráfego HTTP/HTTPS/2/3",
	"banner.platform":        "Plataforma",
	"banner.proxy":           "Proxy",
	"banner.pidFilter":       "Filtro PID",
	"banner.pidNone":         "(nenhum — capturando todos os processos)",
	"banner.caCert":          "Cert. CA",
	"banner.protocols":       "Protocolos",
	"banner.mode":            "Modo",
	"banner.logFile":         "Arquivo de log",
	"banner.modeSystem":      "proxy do sistema",
	"banner.modeExplicit":    "proxy explícito",
	"banner.modeTransparent": " + transparente",
	"banner.caWarn":          "⚠ Um novo CA foi gerado. Instale-o nas autoridades de certificação\n    raiz confiáveis, ou os clientes HTTPS reclamarão do certificado.",
	"banner.installWin":      "Windows: certutil -addstore -f \"ROOT\" %s",
	"banner.installLinux":    "Linux (Debian/Ubuntu): sudo cp %s /usr/local/share/ca-certificates/httpsniff.crt && sudo update-ca-certificates",
	"banner.installMacOS":    "macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s",
	"banner.hotkeys":         "Atalhos: p — definir PID, a — todos os processos, s — status, q/Ctrl+C — sair.",

	"log.request":        "REQUISIÇÃO",
	"log.response":       "RESPOSTA",
	"log.requestBody":    "corpo da requisição",
	"log.responseBody":   "corpo da resposta",
	"log.bytes":          "bytes",
	"log.decoded":        "decodificado: %s",
	"log.binary":         "[dados binários, %d bytes, não exibidos]",
	"log.truncated":      "… truncado (%d de %d bytes)",
	"log.error":          "erro: %v",
	"log.httpsNoDecrypt": "(sem descriptografia)",
	"log.httpsNote":      "corpo criptografado; apenas o host (SNI) é exibido. A descriptografia exige que o app confie no nosso CA.",
	"log.mitmRejected":   "MITM TLS rejeitado pelo app para %s — certificado não confiável; alternando para pass-through neste host",
	"log.mitmHintCA":     "pid %d não é Flutter — o CA precisa ser confiável (curl/navegadores usam o repositório do sistema)",

	"ui.status":         "Filtro: %s   [p] definir PID   [a] todos   [s] status   [q] sair",
	"ui.filterAll":      "todos os processos",
	"ui.filterPID":      "PID %d",
	"ui.logToFile":      "[gravando em arquivo]",
	"ui.captureAll":     "Capturando todos os processos.",
	"ui.help":           "Atalhos: p — PID, a — todos, s — status, q — sair",
	"ui.pidPrompt":      "PID (Enter — todos os processos): ",
	"ui.tuiLogTitle":    " httpsniff — log (↑/↓, PgUp/PgDn, mouse) ",
	"ui.tuiFilterTitle": " Filtrar por processo ",
	"ui.tuiPidLabel":    " PID (vazio = todos): ",
	"ui.tuiError":       "Erro da TUI:",

	"sysproxy.hintWin":         "Proxy do sistema do Windows ativado (WinINET). Navegadores e apps que usam\n  as configurações do sistema passarão pelo interceptador automaticamente.",
	"sysproxy.hintLinux":       "Proxy do sistema do GNOME ativado (gsettings). Para capturar fora do GNOME,\n  use --transparent (iptables REDIRECT).",
	"sysproxy.hintMacOS":       "Proxy do sistema do macOS ativado (networksetup) em todos os serviços de rede ativos.\n  Apps que respeitam o proxy do sistema passam pelo interceptador automaticamente.",
	"sysproxy.errNetworksetup": "networksetup não encontrado; configure o proxy manualmente em Ajustes do Sistema › Rede",
	"sysproxy.errNoServices":   "nenhum serviço de rede ativo encontrado (networksetup)",
	"sysproxy.errGsettings":    "gsettings não encontrado; use --transparent ou configure o proxy manualmente",
	"sysproxy.errUnsupported":  "a configuração automática do proxy do sistema não é suportada nesta plataforma",

	"proxy.quicListen":                "  MITM QUIC/HTTP-3 escutando em udp 127.0.0.1:%d (requer redirecionamento UDP:443 para esta porta)",
	"proxy.transparentWin":            "  Captura transparente via WinDivert ativa (TCP 80/443 → :%d)",
	"proxy.transparentLinux":          "  TCP transparente escutando em %s. Configure o redirecionamento, ex.:\n    sudo iptables -t nat -A OUTPUT -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports %d",
	"proxy.transparentLinuxActive":    "  TCP transparente escutando em %s. iptables REDIRECT configurado automaticamente (TCP 80/443 → :%d). As regras serão removidas ao sair.",
	"proxy.errIptablesNotFound":       "iptables não encontrado; instale o iptables ou configure o redirecionamento manualmente",
	"proxy.errIptablesSetup":          "falha ao configurar iptables REDIRECT: %s",
	"proxy.transparentMacOS":          "  TCP transparente escutando em %s. Configure o redirecionamento do pf, ex.:\n    echo 'rdr pass on lo0 inet proto tcp to any port {80,443} -> 127.0.0.1 port %d' | sudo pfctl -ef -",
	"proxy.errPfOpen":                 "não é possível abrir /dev/pf (o modo transparente requer root)",
	"proxy.errTransparentUnsupported": "o modo transparente não é suportado nesta plataforma",
	"proxy.errWinDivertMissing":       "WinDivert.dll não encontrado ao lado do programa; baixe o WinDivert (https://reqrypt.org/windivert.html), coloque WinDivert.dll e WinDivert64.sys na pasta do httpsniff. Por enquanto usa-se o proxy do sistema (--system-proxy)",
	"proxy.errAdmin":                  "o modo transparente requer execução como administrador",

	"wc.usage": `httpsniff winconfig — isenções de loopback do AppContainer (equivalente ao WinConfig do Fiddler)

Comandos:
  list                exibir todos os AppContainers e seu status de isenção
  exempt-all          permitir loopback para TODOS os apps (Exempt All)
  exempt <texto>      permitir loopback para apps cujo nome/pacote contém <texto>
  clear               remover todas as isenções de loopback

Requer permissões de administrador (exceto list).
`,
	"wc.needSubstr":    "informe um trecho do nome/pacote do app: httpsniff winconfig exempt <texto>",
	"wc.error":         "Erro:",
	"wc.enumErr":       "NetworkIsolationEnumAppContainers retornou o código %d",
	"wc.found":         "AppContainers encontrados: %d (✓ = loopback permitido)",
	"wc.exemptCount":   "Isenções atuais: %d",
	"wc.exemptAllDone": "✓ Exempt All: loopback permitido para %d apps.",
	"wc.noMatch":       "Nenhum app encontrado para \"%s\".",
	"wc.exemptDone":    "Concluído: %d adicionados, %d isenções no total.",
	"wc.cleared":       "Todas as isenções de loopback removidas.",
	"wc.setErr":        "NetworkIsolationSetAppContainerConfig retornou o código %d ",
	"wc.setErrDenied":  "(acesso negado — execute como administrador)",
	"wc.needAdmin":     "⚠ Permissões de administrador necessárias. Inicie o console «como administrador».",

	"up.needPid":    "informe --pid <PID> do app Flutter",
	"up.needAdmin":  "⚠ Permissões de administrador necessárias para escrever na memória do processo.",
	"up.sigErr":     "erro de assinatura:",
	"up.moduleErr":  "flutter_windows.dll não encontrado no processo %d: %v",
	"up.moduleInfo": "flutter_windows.dll: base=0x%X tamanho=%d",
	"up.openErr":    "OpenProcess: %v",
	"up.matches":    "correspondências de assinatura: %d",
	"up.correcting": "função já corrigida por uma versão antiga (retorno 0) — corrigindo para sucesso (1)",
	"up.notFound":   "função de verificação não encontrada — talvez outra versão do Flutter (informe sua própria --sig)",
	"up.multiple":   "várias correspondências — sem patch por precaução. Refine a assinatura (--sig).",
	"up.funcAddr":   "função de verificação do certificado: 0x%X",
	"up.dryRun":     "(dry-run) adicione --apply para aplicar o patch",
	"up.patchErr":   "falha no patch: %v",
	"up.patchOK":    "✓ Verificação TLS desativada. Agora inicie a captura com --tls-mitm.",
	"up.flagPid":    "PID do app Flutter",
	"up.flagApply":  "aplicar o patch (sem a opção — apenas busca/dry-run)",
	"up.flagSig":    "assinatura da função de verificação (hex, ?? — máscara)",
	"up.flagAuto":   "modo automático: tentar todas as assinaturas conhecidas e aplicar",
	"up.flagDump":   "mostrar bytes da função antes/depois do patch (diagnóstico)",

	"up.autoStart":        "Modo automático: testando assinaturas conhecidas de Flutter/BoringSSL…",
	"up.autoAlreadyPatched": "função já corrigida por versão anterior (retorna 0) — corrigindo para retorno 1",
	"up.autoFound":        "✓ Assinatura encontrada: %s — %s",
	"up.autoNotFound":     "nenhuma assinatura conhecida corresponde — talvez versão muito nova do Flutter (informe sua própria --sig)",
	"up.autoDryRun":       "(dry-run) adicione --apply para aplicar o patch",
}
