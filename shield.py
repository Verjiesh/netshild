#!/data/data/com.termux/files/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║  TermuxNetShield — CLI Unificada 🛡️     ║
║  Substitui: install.sh, start.sh,        ║
║  stop.sh, update-blocklist.sh,           ║
║  analyzer.py, pkill -HUP...              ║
║                                           ║
║  Uso: shield <comando> [opções]           ║
╚══════════════════════════════════════════╝
"""

import argparse
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

# ─── Caminhos do projeto ─────────────────────────────────────────────────────
HOME = os.path.expanduser("~")
# Detecta o diretório real onde o script está (funciona com qualquer nome de diretório)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJETO = _SCRIPT_DIR
SCRIPTS_DIR = os.path.join(PROJETO, "scripts")
LOGS_DIR = os.path.join(PROJETO, "logs")
BLOCKLIST_DIR = os.path.join(PROJETO, "blocklists")
RELATORIOS_DIR = os.path.join(PROJETO, "relatorios")
CONFIG_DIR = os.path.join(PROJETO, "config")

LOG_FILE = os.path.join(LOGS_DIR, "dns_server.log")
PID_FILE = os.path.join(LOGS_DIR, "dns_server.pid")
BLOCKLIST_FILE = os.path.join(BLOCKLIST_DIR, "ads.conf")
WHITELIST_FILE = os.path.join(CONFIG_DIR, "whitelist.txt")
CUSTOM_BLOCKLIST_FILE = os.path.join(CONFIG_DIR, "custom_blocklist.txt")
DNS_SERVER_SCRIPT = os.path.join(SCRIPTS_DIR, "dns_server.py")

# ─── Constantes ───────────────────────────────────────────────────────────────
PORTA_PADRAO = 5353
VERSAO = "2.1.0"

# ─── Cores ANSI ──────────────────────────────────────────────────────────────
class Cores:
    VERDE = "\033[0;32m"
    AZUL = "\033[0;34m"
    AMARELO = "\033[1;33m"
    VERMELHO = "\033[0;31m"
    CIANO = "\033[0;36m"
    ROXO = "\033[0;35m"
    NEGRITO = "\033[1m"
    NC = "\033[0m"

    @staticmethod
    def texto(texto, cor):
        return f"{cor}{texto}{Cores.NC}"


def info(msg):
    print(f"{Cores.texto('[INFO]', Cores.AZUL)} {msg}")


def sucesso(msg):
    print(f"{Cores.texto('[OK]', Cores.VERDE)} {msg}")


def aviso(msg):
    print(f"{Cores.texto('[AVISO]', Cores.AMARELO)} {msg}")


def erro(msg):
    print(f"{Cores.texto('[ERRO]', Cores.VERMELHO)} {msg}")


def cabecalho(titulo):
    print()
    print(Cores.texto("═" * 54, Cores.AZUL))
    print(Cores.texto(f"  {titulo}", Cores.AZUL))
    print(Cores.texto("═" * 54, Cores.AZUL))
    print()


# =============================================================================
# Utilitários
# =============================================================================

def _ler_pid():
    """Lê o PID do arquivo. Retorna (pid, None) ou (None, erro_msg)."""
    if not os.path.exists(PID_FILE):
        return None, "PID file não encontrado. O servidor não está rodando."
    try:
        with open(PID_FILE) as f:
            pid = int(f.read().strip())
    except (ValueError, OSError) as e:
        return None, f"Erro ao ler PID file: {e}"
    return pid, None


def _processo_existe(pid):
    """Verifica se um processo com o PID existe."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False
    except PermissionError:
        return False  # sem permissão = processo de outro usuário, tratar como ausente


def _servidor_rodando():
    """Retorna (True, pid) se o servidor está rodando, ou (False, motivo)."""
    pid, err = _ler_pid()
    if pid is None:
        return False, err
    if not _processo_existe(pid):
        return False, f"PID {pid} existe mas processo não está rodando."
    return True, pid


def _encontrar_pid_fallback():
    """Procura o processo dns_server.py via pgrep."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", "dns_server\\.py"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return int(result.stdout.strip().split("\n")[0])
    except (subprocess.SubprocessError, ValueError):
        pass
    return None


def _is_termux():
    return os.path.isdir("/data/data/com.termux")


def _detectar_ip_rede():
    """Detecta o IP do dispositivo na rede local (WiFi)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.connect(("8.8.8.8", 53))
        ip = sock.getsockname()[0]
        sock.close()
        if ip and ip != "127.0.0.1":
            return ip
    except Exception:
        pass
    return None


def _verificar_termux():
    """Avisa se não estiver no Termux."""
    if not _is_termux():
        aviso("Este script foi feito para Termux no Android.")
        aviso("Pode funcionar em outros Linux, mas sem garantia.")


# =============================================================================
# COMANDO: install
# =============================================================================

def cmd_install(args):
    """Instala dependências e configura o projeto."""
    cabecalho("TermuxNetShield — Instalação")

    _verificar_termux()

    # Criar estrutura de diretórios
    info("Criando estrutura de diretórios...")
    for d in [LOGS_DIR, BLOCKLIST_DIR, RELATORIOS_DIR, CONFIG_DIR]:
        os.makedirs(d, exist_ok=True)
    sucesso("Diretórios criados")

    if _is_termux():
        # Atualizar pacotes
        info("Atualizando lista de pacotes...")
        subprocess.run(["pkg", "update", "-y"], capture_output=True)
        sucesso("Pacotes atualizados")

        # Instalar dependências
        info("Instalando dependências...")
        pkgs = ["python", "curl", "git", "jq", "ncurses-utils"]
        result = subprocess.run(
            ["pkg", "install", "-y"] + pkgs,
            capture_output=True, text=True
        )
        if result.returncode != 0:
            erro(f"Falha ao instalar pacotes: {result.stderr}")
            sys.exit(1)
        sucesso("Pacotes do sistema instalados")

    # Instalar dnslib
    info("Instalando dnslib (biblioteca DNS para Python)...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "dnslib"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        erro(f"Falha ao instalar dnslib: {result.stderr}")
        sys.exit(1)
    sucesso("dnslib instalado")

    # Verificar Python e dnslib
    info("Verificando instalação...")
    try:
        import dnslib
        sucesso("dnslib funcionando")
    except ImportError:
        erro("Falha ao importar dnslib")
        sys.exit(1)

    # Dar permissão de execução
    info("Aplicando permissões...")
    for pattern in ["*.sh", "scripts/*.py", "shield*"]:
        for f in Path(PROJETO).glob(pattern):
            f.chmod(0o755)
    sucesso("Permissões aplicadas")

    # Criar whitelist vazia se não existir
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "w") as f:
            f.write("# TermuxNetShield — Whitelist\n")
            f.write("# Domínios nesta lista NÃO serão bloqueados.\n")
            f.write("# Um por linha, ex: doubleclick.net\n")

    # Baixar blocklist inicial
    info("Baixando blocklist inicial (~745k domínios)...")
    cmd_update(args)
    sucesso("Blocklist inicial baixada")

    # Instalar alias/sh
    _instalar_alias()

    # Mensagem final
    print()
    print(Cores.texto("╔══════════════════════════════════════════╗", Cores.VERDE))
    print(Cores.texto("║  Instalação concluída com sucesso! 🛡️   ║", Cores.VERDE))
    print(Cores.texto("╚══════════════════════════════════════════╝", Cores.VERDE))
    print()
    info("Comandos disponíveis:")
    print("  shield start      — Iniciar bloqueio")
    print("  shield stop       — Parar bloqueio")
    print("  shield status     — Ver status")
    print("  shield update     — Atualizar blocklist")
    print("  shield logs -f    — Logs ao vivo")
    print("  shield analyze    — Analisar tráfego")
    print("  shield help       — Ajuda completa")


def _instalar_alias():
    """Cria link simbólico shield → shield.py em local acessível."""
    bashrc = os.path.join(HOME, ".bashrc")
    shield_py = os.path.join(PROJETO, "shield.py")
    shield_wrapper = os.path.join(PROJETO, "shield")

    # Criar wrapper bash (se não existir)
    if not os.path.exists(shield_wrapper):
        with open(shield_wrapper, "w") as f:
            f.write("#!/data/data/com.termux/files/usr/bin/bash\n")
            f.write(f'exec python3 "{shield_py}" "$@"\n')
        os.chmod(shield_wrapper, 0o755)
        sucesso(f"Wrapper criado: {shield_wrapper}")

    # Adicionar PROJETO ao PATH no .bashrc
    path_line = f'export PATH="$PATH:{PROJETO}"'
    if os.path.exists(bashrc):
        with open(bashrc) as f:
            content = f.read()
        if path_line not in content:
            with open(bashrc, "a") as f:
                f.write(f"\n# TermuxNetShield — PATH\n{path_line}\n")
            sucesso("Diretório do projeto adicionado ao PATH no .bashrc")
        else:
            aviso("Diretório do projeto já está no PATH")
    else:
        with open(bashrc, "w") as f:
            f.write(f"# TermuxNetShield — PATH\n{path_line}\n")
        sucesso(f".bashrc criado com PATH para {PROJETO}")

    info("Recarregue o shell ou execute: source ~/.bashrc")


# =============================================================================
# COMANDO: start
# =============================================================================

def cmd_start(args):
    """Inicia o servidor DNS."""
    cabecalho("TermuxNetShield — Iniciando Serviço")

    # Verificar se já está rodando
    rodando, pid_info = _servidor_rodando()
    if rodando:
        aviso(f"Servidor DNS já está rodando (PID: {pid_info})")
        aviso("Reinicie com: shield restart")
        return

    # Verificar se PID está órfão e limpar
    pid, _ = _ler_pid()
    if pid is not None:
        info("Removendo PID obsoleto...")
        os.remove(PID_FILE)

    # Verificar dependências
    try:
        import dnslib
    except ImportError:
        erro("Biblioteca 'dnslib' não instalada. Execute: shield install")
        sys.exit(1)

    # Verificar / criar blocklist
    if not os.path.exists(BLOCKLIST_FILE):
        aviso("Blocklist não encontrada. Baixando agora...")
        cmd_update(args)

    # Verificar whitelist
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "w") as f:
            f.write("# TermuxNetShield — Whitelist\n")

    os.makedirs(LOGS_DIR, exist_ok=True)

    # Iniciar servidor
    port = getattr(args, "port", PORTA_PADRAO)
    host = getattr(args, "host", "127.0.0.1")

    info(f"Iniciando servidor DNS em {host}:{port}...")

    cmd = [
        sys.executable, DNS_SERVER_SCRIPT,
        "--port", str(port),
        "--host", host,
    ]
    if getattr(args, "verbose", False):
        cmd.append("--verbose")
    if not getattr(args, "cname_uncloak", True):
        cmd.append("--no-cname-uncloak")

    processo = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Salvar PID
    with open(PID_FILE, "w") as f:
        f.write(str(processo.pid))

    # Aguardar e verificar
    time.sleep(2)

    if _processo_existe(processo.pid):
        sucesso(f"Servidor DNS rodando (PID: {processo.pid})")

        # Estatísticas da blocklist
        total_dominios = 0
        if os.path.exists(BLOCKLIST_FILE):
            with open(BLOCKLIST_FILE) as f:
                for line in f:
                    if line.startswith("address=/"):
                        total_dominios += 1

        # Whitelist stats
        total_whitelist = 0
        if os.path.exists(WHITELIST_FILE):
            with open(WHITELIST_FILE) as f:
                total_whitelist = sum(
                    1 for line in f
                    if line.strip() and not line.startswith("#")
                )

        print()
        info("Informações:")
        print(f"  DNS local:     {host}:{port}")
        print(f"  Domínios bloqueados: {total_dominios:,}")
        print(f"  Whitelist:     {total_whitelist} domínios")
        print(f"  PID:           {processo.pid}")
        print(f"  Logs:          {LOG_FILE}")
        print()
        info("Comandos úteis:")
        print("  shield logs -f    — Logs ao vivo")
        print("  shield reload     — Recarregar blocklist")
        print("  shield stop       — Parar")
        print("  shield status     — Status completo")
    else:
        erro("Falha ao iniciar servidor DNS.")
        erro(f"Verifique os logs: {LOG_FILE}")
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        sys.exit(1)


# =============================================================================
# COMANDO: network (modo rede)
# =============================================================================

def cmd_network(args):
    """Inicia o servidor DNS para a rede toda."""
    cabecalho("TermuxNetShield — Modo Rede 🌐")

    ip_rede = _detectar_ip_rede()
    if not ip_rede:
        erro("Não foi possível detectar o IP da rede WiFi.")
        erro("Conecte-se a uma rede WiFi e tente novamente.")
        sys.exit(1)

    info(f"IP do dispositivo na rede: {Cores.texto(ip_rede, Cores.VERDE)}")
    print()

    # Iniciar servidor em 0.0.0.0 para toda a rede
    class NetArgs:
        port = PORTA_PADRAO
        host = "0.0.0.0"
        verbose = False
        cname_uncloak = True

    cmd_start(NetArgs())

    # Só mostra info de rede se start foi bem-sucedido
    rodando, pid_info = _servidor_rodando()
    if not rodando:
        return  # cmd_start já mostrou o erro

    print()
    cabecalho("🌐 Configure outros dispositivos")
    print()
    print(f"  {Cores.texto('No WiFi de cada dispositivo:', Cores.NEGRITO)}")
    print(f"    DNS 1 (ou primário): {Cores.texto(ip_rede, Cores.VERDE)}")
    print(f"    Porta:                {Cores.texto(str(PORTA_PADRAO), Cores.VERDE)}")
    print()
    print(f"  Exemplo (Linux/Mac):")
    print(f"    dig @{ip_rede} -p {PORTA_PADRAO} google.com")
    print()
    print(f"  {Cores.texto('⚠️  Este dispositivo Android precisa de um app', Cores.AMARELO)}")
    print(f"  {Cores.texto('para redirecionar o próprio DNS → netshild.', Cores.AMARELO)}")
    print(f"  {Cores.texto('Instale PersonalDNSfilter (F-Droid) e configure:', Cores.CIANO)}")
    print(f"    Upstream DNS: 127.0.0.1:{PORTA_PADRAO}")
    print(f"    Ative a VPN local → tudo bloqueado! 🛡️")
    print()


# =============================================================================
# COMANDO: stop
# =============================================================================

def cmd_stop(args):
    """Para o servidor DNS."""
    cabecalho("TermuxNetShield — Parando Serviço")

    # Coletar estatísticas antes de parar (apenas últimas 50.000 linhas para evitar acumulação)
    bloqueados = 0
    liberados = 0
    total = 0

    if os.path.exists(LOG_FILE):
        try:
            result = subprocess.run(
                ["tail", "-n", "50000", LOG_FILE],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if "🛡️ BLOQUEADO" in line:
                    bloqueados += 1
                elif "✅ LIBERADO" in line:
                    liberados += 1
        except (subprocess.SubprocessError, FileNotFoundError):
            # Fallback: ler arquivo inteiro (lento, mas funciona)
            with open(LOG_FILE, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if "🛡️ BLOQUEADO" in line:
                        bloqueados += 1
                    elif "✅ LIBERADO" in line:
                        liberados += 1
        total = bloqueados + liberados

    pid_encontrado = None

    # Tentar pelo PID file
    pid, _ = _ler_pid()
    if pid is not None and _processo_existe(pid):
        pid_encontrado = pid
        info(f"Parando servidor DNS (PID: {pid})...")
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass

    # Fallback: pgrep
    if pid_encontrado is None:
        fallback_pid = _encontrar_pid_fallback()
        if fallback_pid is not None:
            pid_encontrado = fallback_pid
            info(f"Encontrado processo dns_server.py (PID: {fallback_pid}). Parando...")
            try:
                os.kill(fallback_pid, signal.SIGTERM)
            except OSError:
                pass

    # Aguardar término
    if pid_encontrado is not None:
        for _ in range(5):
            if not _processo_existe(pid_encontrado):
                break
            time.sleep(1)

        # Forçar se necessário
        if _processo_existe(pid_encontrado):
            aviso("Processo não respondeu. Forçando parada (SIGKILL)...")
            try:
                os.kill(pid_encontrado, signal.SIGKILL)
            except OSError:
                pass
            time.sleep(1)

    # Limpeza
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)

    if pid_encontrado is not None:
        sucesso(f"Servidor DNS parado (PID: {pid_encontrado})")
    else:
        aviso("Nenhum servidor DNS em execução.")

    # Estatísticas
    print()
    info("Estatísticas da sessão:")
    print(f"  Total consultas:   {total}")
    print(f"  Bloqueados:        {bloqueados}")
    print(f"  Liberados:         {liberados}")
    if total > 0:
        taxa = (bloqueados * 100) // total
        print(f"  Taxa de bloqueio:  {taxa}%")

    print()
    info("Para análise detalhada: shield analyze")


# =============================================================================
# COMANDO: restart
# =============================================================================

def cmd_restart(args):
    """Reinicia o servidor DNS."""
    cabecalho("TermuxNetShield — Reiniciando")
    cmd_stop(args)
    print()
    cmd_start(args)


# =============================================================================
# COMANDO: status
# =============================================================================

def cmd_status(args):
    """Mostra status detalhado do servidor."""
    cabecalho("TermuxNetShield — Status")

    rodando, pid_info = _servidor_rodando()

    if rodando:
        pid = pid_info
        print(f"  Status:      {Cores.texto('🟢 RODANDO', Cores.VERDE)}")
        print(f"  PID:         {pid}")
        print(f"  Uptime:      {_calcular_uptime()}")
    else:
        # Fallback: procurar por pgrep
        fallback = _encontrar_pid_fallback()
        if fallback is not None:
            print(f"  Status:      {Cores.texto('🟡 RODANDO (PID órfão)', Cores.AMARELO)}")
            print(f"  PID:         {fallback}")
            print(f"  Obs:         PID file ausente. Execute: shield stop && shield start")
            rodando = True
            pid = fallback
        else:
            print(f"  Status:      {Cores.texto('🔴 PARADO', Cores.VERMELHO)}")
            print(f"  Motivo:      {pid_info}")
            rodando = False

    # Estatísticas da blocklist
    if os.path.exists(BLOCKLIST_FILE):
        total_block = 0
        with open(BLOCKLIST_FILE) as f:
            for line in f:
                if line.startswith("address=/"):
                    total_block += 1
        tam = os.path.getsize(BLOCKLIST_FILE)
        print(f"  Blocklist:   {total_block:,} domínios "
              f"({tam / 1024 / 1024:.1f} MB)")

    # Whitelist
    if os.path.exists(WHITELIST_FILE):
        white_count = sum(
            1 for line in open(WHITELIST_FILE)
            if line.strip() and not line.startswith("#")
        )
        print(f"  Whitelist:   {white_count} domínios")

    # Estatísticas de consultas (últimas 1000 linhas do log)
    if os.path.exists(LOG_FILE):
        bloqueados = 0
        liberados = 0
        with open(LOG_FILE, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "🛡️ BLOQUEADO" in line:
                    bloqueados += 1
                elif "✅ LIBERADO" in line:
                    liberados += 1
        total = bloqueados + liberados
        print()
        print(f"  Consultas totais: {total}")
        print(f"  Bloqueados:       {bloqueados}")
        print(f"  Liberados:        {liberados}")
        if total > 0:
            taxa = (bloqueados * 100) / total
            print(f"  Taxa de bloqueio: {taxa:.1f}%")

    # Porta
    print()
    print(f"  DNS local:   127.0.0.1:{PORTA_PADRAO}")
    print(f"  Log:         {LOG_FILE}")
    print(f"  Script:      {DNS_SERVER_SCRIPT}")


def _calcular_uptime():
    """Calcula o uptime do servidor baseado no timestamp do log."""
    if not os.path.exists(LOG_FILE):
        return "desconhecido"
    try:
        with open(LOG_FILE, encoding="utf-8", errors="ignore") as f:
            first_line = f.readline().strip()
        if not first_line:
            return "desconhecido"
        # Formato: "Jan  1 12:34:56 INFO ..."
        match = re.match(r"^(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})", first_line)
        if match:
            from datetime import datetime
            ts = match.group(1)
            ano_atual = datetime.now().year
            inicio = datetime.strptime(f"{ano_atual} {ts}", "%Y %b %d %H:%M:%S")
            agora = datetime.now()
            diff = (agora - inicio).total_seconds()
            if diff < 0:
                diff += 86400
            if diff < 60:
                return f"{diff:.0f}s"
            elif diff < 3600:
                return f"{diff / 60:.0f}m"
            elif diff < 86400:
                return f"{diff / 3600:.1f}h"
            else:
                return f"{diff / 86400:.1f}d"
    except Exception:
        pass
    return "desconhecido"


# =============================================================================
# COMANDO: reload
# =============================================================================

def cmd_reload(args):
    """Recarrega a blocklist via SIGHUP sem reiniciar."""
    cabecalho("TermuxNetShield — Recarregando Blocklist")

    pid, err = _ler_pid()
    if pid is None:
        fallback = _encontrar_pid_fallback()
        if fallback is not None:
            pid = fallback
        else:
            erro("Servidor não está rodando.")
            sys.exit(1)

    try:
        os.kill(pid, signal.SIGHUP)
        sucesso(f"Sinal SIGHUP enviado para PID {pid}.")
        sucesso("Blocklist recarregada em tempo real!")
    except ProcessLookupError:
        erro(f"Processo PID {pid} não encontrado.")
        sys.exit(1)
    except PermissionError:
        erro(f"Permissão negada para enviar sinal ao PID {pid}.")
        sys.exit(1)


# =============================================================================
# COMANDO: update
# =============================================================================

# Modos de bloqueio (tiered blocking — inspirado no uBlock Origin)
MODOS_BLOCKLIST = {
    "light": {
        "descricao": "Leve (~300K dominios, baixo impacto)",
        "fontes": {
            "OISD_Small": ("https://small.oisd.nl/", "adblock"),
        },
    },
    "medium": {
        "descricao": "Moderado (~1.5M dominios, bom equilibrio)",
        "fontes": {
            "OISD_Full": ("https://big.oisd.nl/", "adblock"),
            "AdGuard_DNS": ("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "adguard"),
            "StevenBlack": ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "hosts"),
            "AnudeepND_Ads": ("https://raw.githubusercontent.com/AnudeepND/blacklist/master/adservers.txt", "hosts"),
            "SomeoneWhoCares": ("https://someonewhocares.org/hosts/zero/hosts", "hosts"),
            "1Hosts_Lite": ("https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt", "hosts"),
        },
    },
    "hard": {
        "descricao": "Aggressivo (~3M+ dominios, maxima protecao)",
        "fontes": {
            "OISD_Full": ("https://big.oisd.nl/", "adblock"),
            "AdGuard_DNS": ("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "adguard"),
            "StevenBlack": ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "hosts"),
            "AnudeepND_Ads": ("https://raw.githubusercontent.com/AnudeepND/blacklist/master/adservers.txt", "hosts"),
            "SomeoneWhoCares": ("https://someonewhocares.org/hosts/zero/hosts", "hosts"),
            "1Hosts_Pro": ("https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/hosts.txt", "hosts"),
            "Energized_Basic": ("https://raw.githubusercontent.com/EnergizedProtection/block/master/basic/formats/hosts.txt", "hosts"),
            "URLHaus": ("https://urlhaus.abuse.ch/downloads/hostfile/", "hosts"),
        },
    },
}

# Modo ativo (lido do arquivo de config)
MODO_ATIVO = "medium"

def _get_modo_ativo():
    """Retorna o modo de bloqueio configurado."""
    modo_config = os.path.join(CONFIG_DIR, "mode.txt")
    if os.path.exists(modo_config):
        with open(modo_config) as f:
            modo = f.read().strip().lower()
            if modo in MODOS_BLOCKLIST:
                return modo
    return "medium"  # padrão

def _get_fontes_do_modo(modo=None):
    """Retorna as fontes de blocklist do modo atual."""
    if modo is None:
        modo = _get_modo_ativo()
    if modo not in MODOS_BLOCKLIST:
        modo = "medium"
    return MODOS_BLOCKLIST[modo]["fontes"]

# Para compatibilidade com código existente
FONTES = _get_fontes_do_modo()


def _extrair_dominios(arquivo, formato):
    """Extrai domínios de um arquivo conforme o formato."""
    dominios = set()
    with open(arquivo, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if formato == "hosts":
                # Formato: 0.0.0.0 dominio
                m = re.match(r"^0\.0\.0\.0\s+(\S+)", line)
                if m:
                    dom = m.group(1).lower()
                    if not dom.startswith(("localhost", "broadcasthost", "local", "ip6-", "0.0.0.0")):
                        dominios.add(dom)

            elif formato in ("adblock", "adguard"):
                # Formato: ||dominio^ ou ||dominio^$...
                # Ignorar exceções @@||
                if line.startswith("@@"):
                    continue
                m = re.match(r"^\|\|([^/\^]+)", line)
                if m:
                    dom = m.group(1).lower().strip("^")
                    if dom and "*" not in dom and "/" not in dom and ":" not in dom:
                        dominios.add(dom)

            elif formato == "dominios":
                # Domínio puro por linha
                dom = line.lower().strip("\r")
                if dom and not dom.startswith("#"):
                    dominios.add(dom)

    return dominios


def cmd_update(args):
    """Atualiza a blocklist a partir das fontes."""
    cabecalho("TermuxNetShield — Atualizando Blocklist")
    modo_atual = _get_modo_ativo()
    modo_info = MODOS_BLOCKLIST.get(modo_atual, {})
    desc = modo_info.get("descricao", modo_atual)
    fontes_usadas = _get_fontes_do_modo()
    print(f"  Modo: {Cores.texto(modo_atual.upper(), Cores.ROXO)} — {desc}")
    print(f"  Fontes: {len(fontes_usadas)}")
    print(f"  CNAME Uncloaking: {Cores.texto('ATIVADO', Cores.VERDE)} 🛡️")

    temp_dir = os.path.join(BLOCKLIST_DIR, "tmp")
    os.makedirs(temp_dir, exist_ok=True)

    import urllib.request
    import urllib.error

    total_baixado = 0
    dominios_unicos = set()
    fontes_ok = 0
    fontes_falha = 0

    for nome, (url, formato) in fontes_usadas.items():
        arquivo_temp = os.path.join(temp_dir, f"{nome}.txt")
        sys.stdout.write(f"  [ ] {nome}...\r")
        sys.stdout.flush()

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "TermuxNetShield/2.0"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                content = resp.read()
            with open(arquivo_temp, "wb") as f:
                f.write(content)

            linhas = len(content.decode("utf-8", errors="ignore").splitlines())
            total_baixado += linhas

            # Extrair domínios
            dominios = _extrair_dominios(arquivo_temp, formato)
            dominios_unicos.update(dominios)

            sys.stdout.write(f"  {Cores.texto('[OK]', Cores.VERDE)} {nome} "
                           f"({linhas} linhas, {len(dominios)} domínios extraídos)\n")
            sys.stdout.flush()
            fontes_ok += 1

        except Exception as e:
            sys.stdout.write(f"  {Cores.texto('[FALHA]', Cores.AMARELO)} {nome} "
                           f"({str(e)[:50]})\n")
            sys.stdout.flush()
            fontes_falha += 1
            if os.path.exists(arquivo_temp):
                os.remove(arquivo_temp)

    print()
    info(f"Fontes processadas: {fontes_ok} OK, {fontes_falha} falhas")
    info(f"Total bruto baixado: {total_baixado} linhas")
    info(f"Domínios únicos extraídos: {len(dominios_unicos):,}")

    # Aplicar whitelist (remover domínios que o usuário liberou)
    if os.path.exists(WHITELIST_FILE):
        whitelist = set()
        with open(WHITELIST_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    whitelist.add(line.lower())
        if whitelist:
            antes = len(dominios_unicos)
            dominios_unicos -= whitelist
            removidos = antes - len(dominios_unicos)
            if removidos > 0:
                info(f"Whitelist aplicada: {removidos} domínios preservados")

    # Carregar custom blocklist (domínios extras do usuário)
    if os.path.exists(CUSTOM_BLOCKLIST_FILE):
        with open(CUSTOM_BLOCKLIST_FILE) as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    dominios_unicos.add(line)
        info(f"Custom blocklist carregada")

    # Converter para dnsmasq
    info("Convertendo para formato dnsmasq (address=/dominio/0.0.0.0)...")

    # Ordenar para consistência
    dominios_ordenados = sorted(dominios_unicos)

    with open(BLOCKLIST_FILE, "w", encoding="utf-8") as f:
        f.write("# ===============================================================\n")
        f.write("# TermuxNetShield — Blocklist Pi-hole Style\n")
        f.write(f"# Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Domínios bloqueados: {len(dominios_ordenados):,}\n")
        f.write("# Fontes:\n")
        for nome, (url, _) in fontes_usadas.items():
            f.write(f"#   - {nome}: {url}\n")
        f.write("# ===============================================================\n")
        f.write("\n")
        for dom in dominios_ordenados:
            f.write(f"address=/{dom}/0.0.0.0\n")

    total_final = len(dominios_ordenados)
    tam_mb = os.path.getsize(BLOCKLIST_FILE) / (1024 * 1024)

    sucesso(f"Blocklist final: {total_final:,} regras de bloqueio ({tam_mb:.1f} MB)")

    # Métricas
    print()
    info("Métricas:")
    print(f"  Domínios únicos bloqueados:  {total_final:,}")
    print(f"  Tamanho do arquivo:          {tam_mb:.1f} MB")

    if total_final > 1_000_000:
        print(f"  {Cores.texto('🔥 Cobertura excelente! Comparável ao Pi-hole.', Cores.VERDE)}")
    elif total_final > 500_000:
        print(f"  {Cores.texto('👍 Boa cobertura.', Cores.AMARELO)}")

    # Limpeza
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)

    print()
    info("Para aplicar: shield reload")
    print("  (recarrega a blocklist sem reiniciar o servidor)")


# =============================================================================
# COMANDO: logs
# =============================================================================

def cmd_logs(args):
    """Mostra logs do servidor."""
    if not os.path.exists(LOG_FILE):
        erro("Arquivo de log não encontrado. O servidor já foi iniciado?")
        sys.exit(1)

    if getattr(args, "follow", False):
        # tail -f
        info(f"Logs ao vivo: {LOG_FILE}")
        print("  (Ctrl+C para sair)")
        print()
        try:
            subprocess.run(["tail", "-f", LOG_FILE])
        except KeyboardInterrupt:
            print()
            sucesso("Logs encerrados")
    else:
        # Mostrar últimas N linhas
        n = getattr(args, "lines", 50)
        try:
            result = subprocess.run(
                ["tail", "-n", str(n), LOG_FILE],
                capture_output=True, text=True
            )
            print(result.stdout)
        except subprocess.SubprocessError as e:
            erro(f"Erro ao ler logs: {e}")
            sys.exit(1)


# =============================================================================
# COMANDO: analyze
# =============================================================================

def cmd_analyze(args):
    """Analisa logs e gera relatório."""
    cabecalho("TermuxNetShield — Análise de Logs")

    if not os.path.exists(LOG_FILE):
        erro("Arquivo de log não encontrado.")
        erro("O servidor DNS já foi iniciado? Execute: shield start")
        sys.exit(1)

    # Limpar log com --clear
    if getattr(args, "clear", False):
        open(LOG_FILE, "w").close()
        sucesso("Log limpo!")
        return

    info("Analisando logs...")

    # Parse do log
    dados = _parse_logs(LOG_FILE)

    if dados["total_consultas"] == 0:
        aviso("Nenhuma consulta DNS encontrada no log.")
        aviso("Certifique-se de que o servidor está rodando e há tráfego.")
        sys.exit(0)

    # Estatísticas da blocklist
    total_blocklist = 0
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE) as f:
            for line in f:
                if line.startswith("address=/"):
                    total_blocklist += 1

    _gerar_relatorio(dados, total_blocklist, args.relatorio)


def _parse_logs(caminho_log):
    """Analisa o log e extrai dados estruturados."""
    dados = {
        "total_consultas": 0,
        "dominios_consultados": Counter(),
        "dominios_bloqueados": Counter(),
        "timestamps": [],
    }

    padrao_consulta = re.compile(r"query\[(?:AAAA|A|MX|TXT|CNAME)\]\s+(\S+)")
    padrao_timestamp = re.compile(r"^(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})")

    with open(caminho_log, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            match_ts = padrao_timestamp.search(line)
            if match_ts:
                dados["timestamps"].append(match_ts.group(1))

            match_q = padrao_consulta.search(line)
            if match_q:
                dominio = match_q.group(1).lower()
                dados["dominios_consultados"][dominio] += 1
                dados["total_consultas"] += 1
                if "🛡️ BLOQUEADO" in line or "BLOQUEADO" in line:
                    dados["dominios_bloqueados"][dominio] += 1

    return dados


def _gerar_relatorio(dados, total_blocklist, salvar_arquivo=False):
    """Gera e exibe o relatório."""
    total = dados["total_consultas"]
    bloqueados = sum(dados["dominios_bloqueados"].values())
    liberados = total - bloqueados

    # ── Informações gerais ──
    print(Cores.texto("📊 INFORMAÇÕES GERAIS", Cores.CIANO))
    print(f"  Log analisado:      {LOG_FILE}")

    if dados["timestamps"]:
        print(f"  Primeira consulta:  {dados['timestamps'][0]}")
        print(f"  Última consulta:    {dados['timestamps'][-1]}")

    duracao = 0
    if len(dados["timestamps"]) >= 2:
        try:
            t1, t2 = dados["timestamps"][0], dados["timestamps"][-1]
            ano_atual = datetime.now().year
            dt1 = datetime.strptime(f"{ano_atual} {t1}", "%Y %b %d %H:%M:%S")
            dt2 = datetime.strptime(f"{ano_atual} {t2}", "%Y %b %d %H:%M:%S")
            duracao = (dt2 - dt1).total_seconds()
            if duracao < 0:
                duracao += 86400
            if duracao > 0:
                print(f"  Período analisado:  ~{duracao / 60:.0f} minutos")
        except ValueError:
            pass

    print()

    # ── Estatísticas de consultas ──
    print(Cores.texto("🔍 ESTATÍSTICAS DE CONSULTAS", Cores.CIANO))
    print(f"  Total consultas:    {total}")
    print(f"  Domínios únicos:    {len(dados['dominios_consultados'])}")
    print(f"  Bloqueados 🛡️:     {Cores.texto(str(bloqueados), Cores.VERDE)}")
    print(f"  Liberados ✅:       {liberados}")

    if total > 0:
        taxa_bloqueio = (bloqueados / total) * 100
        qps = total / duracao if duracao > 0 else 0
        print(f"  Taxa de bloqueio:   {taxa_bloqueio:.1f}%")
        print(f"  Consultas/minuto:   {qps * 60:.1f}")
    print()

    # ── Top 10 consultados ──
    print(Cores.texto("🏆 TOP 10 DOMÍNIOS MAIS CONSULTADOS", Cores.CIANO))
    top_consultados = dados["dominios_consultados"].most_common(10)
    if top_consultados:
        for i, (dominio, qtd) in enumerate(top_consultados, 1):
            eh_bloqueado = " 🛡️" if dominio in dados["dominios_bloqueados"] else ""
            print(f"  {i:2d}. {dominio:<40s} {qtd:>5d}x{eh_bloqueado}")
    else:
        print("  (Nenhuma consulta registrada)")
    print()

    # ── Top 10 bloqueios ──
    print(Cores.texto("🚫 TOP 10 DOMÍNIOS BLOQUEADOS", Cores.CIANO))
    top_bloqueados = dados["dominios_bloqueados"].most_common(10)
    if top_bloqueados:
        for i, (dominio, qtd) in enumerate(top_bloqueados, 1):
            print(f"  {i:2d}. {dominio:<40s} {qtd:>5d}x 🛡️")
    else:
        print("  (Nenhum bloqueio registrado)")
    print()

    # ── Blocklist ──
    print(Cores.texto("📋 BLOCKLIST", Cores.CIANO))
    print(f"  Total domínios bloqueados: {total_blocklist:,}")
    print()

    # ── Recomendações ──
    print(Cores.texto("💡 RECOMENDAÇÕES", Cores.CIANO))
    if total > 0:
        if bloqueados / total < 0.05:
            print("  • Taxa de bloqueio baixa — considere adicionar mais")
            print("    fontes com: shield update")
        elif bloqueados / total > 0.50:
            print("  • Taxa de bloqueio alta! Verifique se sites")
            print("    legítimos estão sendo bloqueados.")
            print("    Use: shield whitelist add <dominio>")
        if total > 1000:
            print("  • Alto volume de consultas — o cache DNS está")
            print("    ajudando a reduzir tráfego para upstreams.")
    print()

    # ── Salvar relatório ──
    if salvar_arquivo:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs(RELATORIOS_DIR, exist_ok=True)
        caminho = os.path.join(RELATORIOS_DIR, f"relatorio_{timestamp}.txt")
        with open(caminho, "w", encoding="utf-8") as f:
            f.write(f"Relatório TermuxNetShield - {datetime.now()}\n")
            f.write("=" * 50 + "\n")
            f.write(f"Total consultas: {total}\n")
            f.write(f"Bloqueados: {bloqueados}\n")
            f.write(f"Taxa bloqueio: {bloqueados / total * 100:.1f}%\n")
            f.write(f"\nTop 10 bloqueados:\n")
            for dom, qtd in top_bloqueados:
                f.write(f"  {dom} - {qtd}x\n")
        sucesso(f"Relatório salvo em: {caminho}")

    # Resumo final
    print(Cores.texto("─" * 54, Cores.AZUL))
    print(Cores.texto("  ✅ ANÁLISE CONCLUÍDA", Cores.VERDE))
    print(Cores.texto("─" * 54, Cores.AZUL))


# =============================================================================
# COMANDO: whitelist
# =============================================================================

def cmd_whitelist(args):
    """Gerencia a whitelist de domínios."""
    if not hasattr(args, "subcomando"):
        _whitelist_list()
        return

    if args.subcomando == "list":
        _whitelist_list()
    elif args.subcomando == "add":
        _whitelist_add(args.dominio)
    elif args.subcomando == "remove":
        _whitelist_remove(args.dominio)


def _carregar_whitelist():
    """Carrega a whitelist como um set."""
    whitelist = set()
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    whitelist.add(line.lower())
    return whitelist


def _salvar_whitelist(whitelist):
    """Salva a whitelist ordenada."""
    os.makedirs(os.path.dirname(WHITELIST_FILE), exist_ok=True)
    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        f.write("# TermuxNetShield — Whitelist\n")
        f.write("# Domínios nesta lista NÃO serão bloqueados.\n")
        f.write("# Um por linha, ex: doubleclick.net\n")
        f.write("\n")
        for dom in sorted(whitelist):
            f.write(f"{dom}\n")


def _whitelist_list():
    """Lista a whitelist."""
    cabecalho("TermuxNetShield — Whitelist")
    whitelist = _carregar_whitelist()
    if whitelist:
        print(f"  {len(whitelist)} domínios na whitelist:\n")
        for dom in sorted(whitelist):
            print(f"    • {dom}")
    else:
        print("  (vazia — nenhum domínio na whitelist)")
    print()
    info("Para adicionar: shield whitelist add <dominio>")
    info("Para remover:   shield whitelist remove <dominio>")


def _whitelist_add(dominio):
    """Adiciona um domínio à whitelist."""
    dominio = dominio.lower().strip().lstrip("*.")
    whitelist = _carregar_whitelist()
    if dominio in whitelist:
        aviso(f"'{dominio}' já está na whitelist.")
        return
    whitelist.add(dominio)
    _salvar_whitelist(whitelist)
    sucesso(f"'{dominio}' adicionado à whitelist!")

    # Remover da blocklist atualmente carregada (se servidor rodando)
    rodando, _ = _servidor_rodando()
    if rodando:
        print()
        info("Para aplicar imediatamente: shield reload")
        info("(A blocklist será reconstruída na próxima atualização)")


def _whitelist_remove(dominio):
    """Remove um domínio da whitelist."""
    dominio = dominio.lower().strip()
    whitelist = _carregar_whitelist()
    if dominio not in whitelist:
        aviso(f"'{dominio}' não está na whitelist.")
        return
    whitelist.discard(dominio)
    _salvar_whitelist(whitelist)
    sucesso(f"'{dominio}' removido da whitelist!")

    rodando, _ = _servidor_rodando()
    if rodando:
        print()
        info("Para aplicar imediatamente (reconstruir blocklist):")
        info("  shield update && shield reload")


# =============================================================================
# COMANDO: config
# =============================================================================

def _cmd_config_set_modo(modo):
    """Altera o modo de bloqueio."""
    if modo not in MODOS_BLOCKLIST:
        erro(f"Modo invalido: '{modo}'")
        info("Modos disponiveis:")
        for m, info in MODOS_BLOCKLIST.items():
            print(f"  {Cores.texto(m, Cores.ROXO)} — {info['descricao']}")
        return
    
    modo_config = os.path.join(CONFIG_DIR, "mode.txt")
    with open(modo_config, "w") as f:
        f.write(modo.strip().lower() + "\n")
    
    sucesso(f"Modo de bloqueio alterado para: {Cores.texto(modo.upper(), Cores.ROXO)}")
    sucesso(f"  {MODOS_BLOCKLIST[modo]['descricao']}")
    print()
    info("Para aplicar o novo modo:")
    print("  shield update   (baixar novas blocklists)")
    print("  shield reload   (recarregar sem reiniciar)")
    print()
    info("Para ver o modo atual: shield config")

def cmd_config(args):
    """Mostra configuração atual do projeto ou altera modo de bloqueio."""
    modo_arg = getattr(args, "modo", None)
    if modo_arg is not None:
        return _cmd_config_set_modo(modo_arg)
    
    cabecalho("TermuxNetShield — Configuração")

    print(Cores.texto("📍 DIRETÓRIOS", Cores.CIANO))
    print(f"  Projeto:        {PROJETO}")
    print(f"  Scripts:        {SCRIPTS_DIR}")
    print(f"  Logs:           {LOGS_DIR}")
    print(f"  Blocklists:     {BLOCKLIST_DIR}")
    print(f"  Relatórios:     {RELATORIOS_DIR}")
    print(f"  Config:         {CONFIG_DIR}")
    print()

    print(Cores.texto("📄 ARQUIVOS", Cores.CIANO))
    for nome, path in [
        ("Servidor DNS", DNS_SERVER_SCRIPT),
        ("CLI principal", os.path.join(PROJETO, "shield.py")),
        ("Blocklist", BLOCKLIST_FILE),
        ("Whitelist", WHITELIST_FILE),
        ("Custom blocklist", CUSTOM_BLOCKLIST_FILE),
        ("Log", LOG_FILE),
        ("PID", PID_FILE),
        ("Config DNS", os.path.join(CONFIG_DIR, "dnsmasq.conf")),
        ("Modo bloqueio", os.path.join(CONFIG_DIR, "mode.txt")),
    ]:
        existe = os.path.exists(path)
        status = "✅" if existe else "❌"
        tam = ""
        if existe and os.path.isfile(path):
            kb = os.path.getsize(path) / 1024
            if kb > 1024:
                tam = f" ({kb / 1024:.1f} MB)"
            else:
                tam = f" ({kb:.0f} KB)"
        print(f"  {status} {nome:<20s} {path}{tam}")
    print()

    print(Cores.texto("⚙️  DNS", Cores.CIANO))
    print(f"  Porta:          {PORTA_PADRAO}")
    print(f"  Upstreams:      1.1.1.1, 1.0.0.1, 8.8.8.8 (porta 53)")
    print()

    print(Cores.texto("🛡️  BLOQUEIO", Cores.CIANO))
    modo_atual = _get_modo_ativo()
    modo_info = MODOS_BLOCKLIST.get(modo_atual, {})
    desc = modo_info.get("descricao", modo_atual)
    print(f"  Modo:           {Cores.texto(modo_atual.upper(), Cores.ROXO)} — {desc}")
    print(f"  CNAME Uncloak:  {Cores.texto('ATIVADO', Cores.VERDE)} 🛡️")
    print()
    print(f"  Para mudar:     shield config set mode <light|medium|hard>")

    print(Cores.texto("🔗 COMANDO GLOBAL", Cores.CIANO))
    # Verificar se shield está no PATH
    shield_path = os.path.join(PROJETO, "shield")
    if os.path.exists(shield_path):
        if _is_termux():
            in_path = PROJETO in os.environ.get("PATH", "")
            status = "✅ no PATH" if in_path else "⚠️  não está no PATH"
            print(f"  shield:         {shield_path} ({status})")
        else:
            print(f"  shield:         {shield_path}")
    else:
        print(f"  shield:         {Cores.texto('❌ não encontrado', Cores.VERMELHO)}")

    # Verificar versões
    print()
    print(Cores.texto("📦 DEPENDÊNCIAS", Cores.CIANO))
    try:
        import dnslib
        print(f"  dnslib:         ✅ (versão {dnslib.__version__})")
    except (ImportError, AttributeError):
        print(f"  dnslib:         ❌ não instalado")
    print(f"  Python:         {sys.version.split()[0]}")
    print(f"  CLI versão:     {VERSAO}")


# =============================================================================
# COMANDO: uninstall
# =============================================================================

def cmd_uninstall(args):
    """Remove o TermuxNetShield completamente."""
    cabecalho("TermuxNetShield — Desinstalação")

    print(Cores.texto("⚠️  ISSO REMOVERÁ TODO O PROJETO PERMANENTEMENTE!", Cores.VERMELHO))
    print()
    confirm = input("  Digite 'sim' para confirmar: ").strip().lower()
    if confirm != "sim":
        aviso("Desinstalação cancelada.")
        return

    # Parar servidor se rodando
    rodando, pid_info = _servidor_rodando()
    if rodando:
        info("Parando servidor DNS...")
        cmd_stop(args)

    # Remover alias do .bashrc
    bashrc = os.path.join(HOME, ".bashrc")
    if os.path.exists(bashrc):
        with open(bashrc) as f:
            lines = f.readlines()
        new_lines = []
        in_block = False
        for line in lines:
            if "TermuxNetShield" in line:
                in_block = True
                continue
            if in_block and line.strip().startswith("export PATH="):
                in_block = False
                continue
            if not in_block:
                new_lines.append(line)
        with open(bashrc, "w") as f:
            f.writelines(new_lines)
        sucesso("Alias removido do .bashrc")

    # Remover diretório do projeto
    import shutil
    info("Removendo diretório do projeto...")
    shutil.rmtree(PROJETO, ignore_errors=True)
    sucesso(f"Diretório {PROJETO} removido")

    print()
    print(Cores.texto("  TermuxNetShield foi removido. 🗑️", Cores.AMARELO))
    print()
    print("  Recarregue o shell: source ~/.bashrc")


# =============================================================================
# COMANDO: stats (quick)
# =============================================================================

def cmd_stats(args):
    """Mostra estatísticas rápidas (versão compacta do analyze)."""
    if not os.path.exists(LOG_FILE):
        erro("Log não encontrado.")
        return

    # Últimas 5000 linhas para stats rápidos
    bloqueados = 0
    liberados = 0
    dominios = Counter()
    ultimos = []

    try:
        result = subprocess.run(
            ["tail", "-n", "5000", LOG_FILE],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if "🛡️ BLOQUEADO" in line:
                bloqueados += 1
                # Extrair domínio
                m = re.search(r"BLOQUEADO:\s+(\S+)", line)
                if m:
                    dominios[m.group(1)] += 1
                    ultimos.append(("🛡️", m.group(1)))
            elif "✅ LIBERADO" in line:
                liberados += 1
                m = re.search(r"LIBERADO:\s+(\S+)", line)
                if m:
                    ultimos.append(("✅", m.group(1)))

        total = bloqueados + liberados
        print()
        print(f"  📊 Últimas consultas (5000 linhas)")
        print(f"  {'─' * 40}")
        print(f"  Total:    {total}")
        print(f"  🛡️  Bloqueados: {bloqueados}")
        print(f"  ✅ Liberados:  {liberados}")
        if total > 0:
            print(f"  📈 Taxa:    {bloqueados * 100 // total}%")
        print()

        # Top bloqueados
        if dominios:
            print(f"  🚫 Top 5 bloqueados nas últimas consultas:")
            for dom, qtd in dominios.most_common(5):
                print(f"     {dom:<40s} {qtd:>4d}x 🛡️")

    except subprocess.SubprocessError:
        erro("Erro ao ler logs.")


# =============================================================================
# COMANDO: boot-enable / boot-disable
# =============================================================================

BOOT_DIR = os.path.expanduser("~/.termux/boot")
BOOT_SCRIPT_SRC = os.path.join(SCRIPTS_DIR, "boot-start.sh")

def cmd_boot_enable(args):
    """Instala auto-start na inicialização do Android (Termux:Boot)."""
    cabecalho("TermuxNetShield — Auto-start")

    boot_dir = BOOT_DIR
    os.makedirs(boot_dir, exist_ok=True)

    destino = os.path.join(boot_dir, "netshild-start.sh")

    if os.path.exists(destino):
        aviso("Auto-start já está instalado.")
        info(f"Arquivo: {destino}")
        return

    if not os.path.exists(BOOT_SCRIPT_SRC):
        erro(f"Script de boot não encontrado: {BOOT_SCRIPT_SRC}")
        sys.exit(1)

    import shutil
    shutil.copy2(BOOT_SCRIPT_SRC, destino)
    os.chmod(destino, 0o755)
    sucesso(f"Auto-start instalado em:\n  {destino}")
    print()
    info("O netshild iniciará automaticamente ao ligar o celular.")
    info("Certifique-se de que o app Termux:Boot (F-Droid) está instalado")
    info("e que o Termux tem permissão para iniciar na inicialização.")
    print()
    info("Para remover: shield boot-disable")


def cmd_boot_disable(args):
    """Remove auto-start da inicialização."""
    cabecalho("TermuxNetShield — Remover Auto-start")

    destino = os.path.join(BOOT_DIR, "netshild-start.sh")
    if os.path.exists(destino):
        os.remove(destino)
        sucesso("Auto-start removido.")
    else:
        aviso("Auto-start não está instalado.")
    print()
    info("Para reinstalar: shield boot-enable")


# =============================================================================
# COMANDO: dns-self (DNS-over-TLS + Private DNS)
# =============================================================================

DOT_PROXY_SCRIPT = os.path.join(SCRIPTS_DIR, "dot_proxy.py")

def cmd_dns_self(args):
    """Configura DNS-over-TLS para usar o Private DNS do Android."""
    cabecalho("TermuxNetShield — DNS Self 🛡️")

    if not os.path.exists(DOT_PROXY_SCRIPT):
        erro(f"Proxy DoT não encontrado: {DOT_PROXY_SCRIPT}")
        sys.exit(1)

    # Verificar dependências
    try:
        subprocess.run(["openssl", "version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.SubprocessError):
        erro("OpenSSL não encontrado. Instale com: pkg install openssl-tool")
        sys.exit(1)

    # ── Gerar certificados (se não existirem) ──
    certs_dir = os.path.join(CONFIG_DIR, "certs")
    ca_der = os.path.join(certs_dir, "ca-cert.der")

    if not os.path.exists(ca_der):
        info("Gerando certificados CA + servidor (válidos por 10 anos)...")
        result = subprocess.run(
            [sys.executable, DOT_PROXY_SCRIPT, "--gen-certs"],
            capture_output=True, text=True, timeout=30
        )
        print(result.stdout)
        if result.returncode != 0:
            erro(f"Falha ao gerar certificados: {result.stderr}")
            sys.exit(1)
        sucesso("Certificados gerados!")
    else:
        sucesso("Certificados já existem")

    # ── Verificar se netshild está rodando ──
    rodando, pid_info = _servidor_rodando()
    if not rodando:
        print()
        info("Iniciando netshild (servidor DNS bloqueador)...")
        class StartArgs:
            port = PORTA_PADRAO
            host = "127.0.0.1"
            verbose = False
            cname_uncloak = True
        cmd_start(StartArgs())

        rodando, pid_info = _servidor_rodando()
        if not rodando:
            erro("Falha ao iniciar netshild.")
            sys.exit(1)

    # ── Copiar CA para download ──
    download_path = os.path.join(HOME, "storage", "downloads", "netshield-ca.der")
    try:
        import shutil
        os.makedirs(os.path.dirname(download_path), exist_ok=True)
        shutil.copy2(ca_der, download_path)
        sucesso(f"CA copiada para Downloads: {download_path}")
    except Exception as e:
        aviso(f"Não foi possível copiar CA para Downloads: {e}")
        info(f"CA disponível em: {ca_der}")

    # ── Detectar IP ──
    ip_rede = _detectar_ip_rede() or "127.0.0.1"
    hostname_dns = f"{ip_rede}.nip.io"

    # ── Iniciar DoT proxy em background ──
    print()
    info("Iniciando proxy DNS-over-TLS (porta 853)...")
    log_path = os.path.join(LOGS_DIR, "dot_proxy.log")
    processo = subprocess.Popen(
        [sys.executable, DOT_PROXY_SCRIPT],
        stdout=open(log_path, "a"),
        stderr=subprocess.STDOUT,
    )

    # Aguardar inicialização
    import time
    time.sleep(2)

    if processo.poll() is None:
        sucesso(f"Proxy DoT rodando (PID: {processo.pid})")
        # ── Mostrar instruções ──
        print()
        print(Cores.texto("╔══════════════════════════════════════════════════════╗", Cores.VERDE))
        print(Cores.texto("║  ✅ Tudo pronto! Configure o Private DNS agora:    ║", Cores.VERDE))
        print(Cores.texto("╚══════════════════════════════════════════════════════╝", Cores.VERDE))
        print()
        print(f"  {Cores.texto('Passo 1 — Instalar certificado CA no Android:', Cores.NEGRITO)}")
        print(f"    1. Abra o app 'Arquivos' → Downloads → netshield-ca.der")
        print(f"    2. Toque no arquivo → 'Instalar certificado' → Confirme")
        print(f"    (ou: Ajustes → Segurança → Credenciais → Instalar)")
        print()
        print(f"  {Cores.texto('Passo 2 — Configurar Private DNS:', Cores.NEGRITO)}")
        print(f"    Ajustes → Rede → DNS Privado → {Cores.texto(hostname_dns, Cores.CIANO)}")
        print()
        print(f"  {Cores.texto('Passo 3 — Testar (após configurar):', Cores.NEGRITO)}")
        print(f"    Acesse um site com anúncios → tudo bloqueado! 🛡️")
        print()
        print(f"  Para ver logs do DoT:")
        print(f"    tail -f {log_path}")
        print()
    else:
        aviso("Proxy DoT não pode usar porta 853 (EXIGE ROOT).")
        print()
        print(Cores.texto("╔══════════════════════════════════════════════════════╗", Cores.AMARELO))
        print(Cores.texto("║  ⚠️  Private DNS exige porta 853 (porta privilegiada) ║", Cores.AMARELO))
        print(Cores.texto("║  Sem root no Android, não é possível usar DoT.      ║", Cores.AMARELO))
        print(Cores.texto("╚══════════════════════════════════════════════════════╝", Cores.AMARELO))
        print()
        print(f"  {Cores.texto('O que funciona AGORA sem root:', Cores.VERDE)}")
        print(f"  {Cores.texto('1. shield network', Cores.CIANO)} — Bloqueia anúncios na REDE WiFi toda")
        print(f"     Outros dispositivos usam 192.168.1.4:5353 como DNS")
        print(f"     (configure manualmente no WiFi de cada um)")
        print()
        print(f"  {Cores.texto('2. shield start', Cores.CIANO)} — Bloqueia neste celular")
        print(f"     Para apps que aceitam DNS customizado (browsers, etc.)")
        print(f"     Configure o DNS como 127.0.0.1:5353 no app")
        print()
        print(f"  {Cores.texto('3. Para bloquear TUDO neste celular sem root:', Cores.NEGRITO)}")
        print(f"     Instale PersonalDNSfilter (F-Droid, gratuito)")
        print(f"     Configure upstream → 127.0.0.1:5353")
        print(f"     Ative a VPN → TODO tráfego DNS passa pelo netshild! 🛡️")
        print()
        print(f"  (PersonalDNSfilter não é um app de bloqueio — é um")
        print(f"   redirecionador de DNS, e o bloqueio é feito pelo netshild)")
        print()


# =============================================================================
# COMANDO: help
# =============================================================================

def cmd_help(args):
    """Mostra ajuda completa."""
    cabecalho("TermuxNetShield 🛡️ — Ajuda")
    print(f"  Versão: {VERSAO}")
    print()
    print(Cores.texto("USO:", Cores.NEGRITO))
    print("  shield <comando> [opções]")
    print()
    print(Cores.texto("GERENCIAMENTO:", Cores.CIANO))
    print("  install              Instalar dependências e configurar projeto")
    print("  uninstall            Remover completamente o projeto")
    print()
    print(Cores.texto("SERVIÇO DNS:", Cores.CIANO))
    print("  start                Iniciar servidor DNS (porta 5353, apenas local)")
    print("  network              Iniciar servidor DNS para toda a rede WiFi 🌐")
    print("  stop                 Parar servidor DNS")
    print("  restart              Reiniciar servidor DNS")
    print("  status               Mostrar status detalhado do servidor")
    print("  reload               Recarregar blocklist sem reiniciar")
    print()
    print(Cores.texto("BLOCKLIST:", Cores.CIANO))
    print("  update               Baixar e atualizar blocklist (~2M domínios)")
    print("  whitelist list       Listar domínios na whitelist")
    print("  whitelist add <dom>  Adicionar domínio à whitelist")
    print("  whitelist rem <dom>  Remover domínio da whitelist")
    print()
    print(Cores.texto("ANÁLISE E LOGS:", Cores.CIANO))
    print("  analyze              Analisar logs e gerar relatório completo")
    print("  analyze --report     Salvar relatório em arquivo")
    print("  analyze --clear      Limpar arquivo de log")
    print("  stats                Estatísticas rápidas (últimas consultas)")
    print("  logs                 Mostrar últimas 50 linhas do log")
    print("  logs -f              Logs ao vivo (tail -f)")
    print()
    print(Cores.texto("CONFIGURAÇÃO:", Cores.CIANO))
    print("  config               Mostrar configuração e caminhos do projeto")
    print("  config set mode <m>  Alterar modo de bloqueio")
    print("                     light  — Leve (~300K dominios)")
    print("                     medium — Moderado (~1.5M dominios)")
    print("                     hard   — Agressivo (~3M+ dominios)")
    print()
    print(Cores.texto("RECURSOS AVANÇADOS:", Cores.CIANO))
    print("  CNAME Uncloaking     Detecta trackers escondidos atrás de CNAMEs")
    print("                       (ativado por padrão)")
    print("  shield start --no-cname-uncloak")
    print("                       Desativar CNAME uncloaking (economiza bateria)")
    print()
    print(Cores.texto("AUTO-START (Termux:Boot):", Cores.CIANO))
    print("  boot-enable          Instalar auto-start na inicialização do Android")
    print("  boot-disable         Remover auto-start")
    print("  (Requer Termux:Boot instalado da F-Droid)")
    print()
    print(Cores.texto("DNS PRIVADO (sem root, sem apps):", Cores.CIANO))
    print("  dns-self             Configurar DNS-over-TLS + Private DNS nativo")
    print("                       Faz todo o Android usar o netshild 🛡️")
    print()
    print(Cores.texto("EXEMPLOS:", Cores.NEGRITO))
    print("  shield start         # Iniciar bloqueio")
    print("  shield status        # Ver se está rodando")
    print("  shield logs -f       # Acompanhar bloqueios ao vivo")
    print("  shield whitelist add doubleclick.net")
    print("  shield update && shield reload")
    print("  shield analyze       # Ver estatísticas")
    print()


# =============================================================================
# Ponto de entrada principal
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="TermuxNetShield 🛡️ — CLI unificada",
        add_help=False,
    )
    parser.add_argument("comando", nargs="?", default="help",
                        help="Comando a executar")
    # args conhecidos primeiro, resto fica para subcomandos
    args, rest = parser.parse_known_args()

    comando = args.comando

    # ── Roteamento de comandos ──────────────────────────────────────────────
    if comando in ("install", "instalar", "setup"):
        cmd_install(args)

    elif comando == "start":
        p = argparse.ArgumentParser()
        p.add_argument("--port", type=int, default=PORTA_PADRAO)
        p.add_argument("--host", default="127.0.0.1")
        p.add_argument("--verbose", "-v", action="store_true")
        p.add_argument("--cname-uncloak", default=None, action="store_true")
        p.add_argument("--no-cname-uncloak", dest="cname_uncloak", action="store_false")
        subargs = p.parse_args(rest)
        cmd_start(subargs)

    elif comando == "network":
        cmd_network(args)

    elif comando == "boot-enable":
        cmd_boot_enable(args)

    elif comando == "boot-disable":
        cmd_boot_disable(args)

    elif comando in ("dns-self", "private-dns", "dot"):
        cmd_dns_self(args)

    elif comando == "stop":
        cmd_stop(args)

    elif comando == "restart":
        cmd_restart(args)

    elif comando == "status":
        cmd_status(args)

    elif comando == "reload":
        cmd_reload(args)

    elif comando in ("update", "atualizar"):
        cmd_update(args)

    elif comando == "logs":
        p = argparse.ArgumentParser()
        p.add_argument("-f", "--follow", action="store_true")
        p.add_argument("-n", "--lines", type=int, default=50)
        subargs = p.parse_args(rest)
        cmd_logs(subargs)

    elif comando == "analyze":
        p = argparse.ArgumentParser()
        p.add_argument("--report", "-r", action="store_true")
        p.add_argument("--clear", "-c", action="store_true")
        subargs = p.parse_args(rest)
        cmd_analyze(subargs)

    elif comando == "stats":
        cmd_stats(args)

    elif comando == "whitelist":
        if not rest:
            sub = "list"
            sub_rest = []
        else:
            sub = rest[0]
            sub_rest = rest[1:]

        p = argparse.ArgumentParser()
        p.add_argument("subcomando", nargs="?")
        p.add_argument("dominio", nargs="?")
        subargs = p.parse_args([sub] + sub_rest)
        subargs.subcomando = sub
        subargs.dominio = sub_rest[0] if sub_rest else None
        cmd_whitelist(subargs)

    elif comando in ("config", "cfg"):
        if rest and len(rest) >= 3 and rest[0] == "set" and rest[1] == "mode":
            modo = rest[2].strip().lower()
            if modo in MODOS_BLOCKLIST:
                class ConfigArgs:
                    pass
                setattr(ConfigArgs, "modo", modo)
                cmd_config(ConfigArgs())
            else:
                erro(f"Modo inválido: '{modo}'")
                info("Modos disponíveis: light, medium, hard")
        else:
            cmd_config(args)

    elif comando == "uninstall":
        cmd_uninstall(args)

    elif comando in ("help", "--help", "-h", None):
        cmd_help(args)

    else:
        erro(f"Comando desconhecido: '{comando}'")
        print()
        info("Comandos disponíveis:")
        print("  install, start, network, stop, restart, status, reload,")
        print("  update, logs, analyze, stats, whitelist, config,")
        print("  dns-self, boot-enable, boot-disable, uninstall, help")
        print()
        info("Use: shield help  (para ajuda detalhada)")
        sys.exit(1)


if __name__ == "__main__":
    main()
