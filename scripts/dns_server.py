#!/data/data/com.termux/files/usr/bin/env python3
"""
TermuxNetShield — DNS Server
=============================
Servidor DNS local em Python que bloqueia anúncios via blocklist.
Alternativa ao dnsmasq (não disponível no Termux).

Funcionamento:
  1. Recebe consultas DNS na porta 5353 (UDP)
  2. Verifica se o domínio está na blocklist
  3. Se bloqueado → responde com 0.0.0.0 (NXDOMAIN)
  4. Se liberado → encaminha para upstream (Cloudflare/Google)
  5. Registra tudo no arquivo de log

Dependências: pip install dnslib
"""

import os
import re
import sys
import signal
import socket
import logging
import argparse
from datetime import datetime

try:
    from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, AAAA, RCODE
except ImportError:
    print("ERRO: Biblioteca 'dnslib' não instalada.")
    print("Execute: pip install dnslib")
    sys.exit(1)


# ─── Diretórios e arquivos ───────────────────────────────────────────────────
HOME = os.path.expanduser("~")
# Detecta o diretório raiz do projeto (sobe 2 níveis: scripts/dns_server.py → projeto/)
PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLOCKLIST_PATH = os.path.join(PROJETO, "blocklists", "ads.conf")
WHITELIST_PATH = os.path.join(PROJETO, "config", "whitelist.txt")
LOG_PATH = os.path.join(PROJETO, "logs", "dns_server.log")
PID_PATH = os.path.join(PROJETO, "logs", "dns_server.pid")

# Garantir que diretórios existam
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

# ─── Configurações padrão ───────────────────────────────────────────────────
PORTA_PADRAO = 5353
UPSTREAM_DNS = [
    ("1.1.1.1", 53),     # Cloudflare
    ("1.0.0.1", 53),     # Cloudflare fallback
    ("8.8.8.8", 53),     # Google
]
TIMEOUT_UPSTREAM = 2.0  # segundos

# CNAME Uncloaking — quando ativado, resolve a cadeia CNAME de domínios
# não-bloqueados e verifica se o destino final está na blocklist.
# Muitos trackers usam CNAMEs para disfarçar (ex: analitica.banco.com → tracker.ads.com)
CNAME_UNCLOAK = True  # Pode ser desligado com --no-cname-uncloak

# Estatísticas por cliente (IP → contagem)
ESTATISTICAS_CLIENTES = {}


# =============================================================================
# Blocklist Manager
# =============================================================================
class BlocklistManager:
    """
    Gerencia a lista de domínios bloqueados.
    Carrega do arquivo ads.conf (formato dnsmasq: address=/dominio/0.0.0.0).
    """

    def __init__(self, caminho, whitelist_path=None):
        self.caminho = caminho
        self.whitelist_path = whitelist_path
        self.dominios = set()
        self.whitelist = set()
        self.padrao = re.compile(r"address=/([^/]+)/")
        self.total = 0
        self.carregar()
        self._carregar_whitelist()

    def carregar(self):
        """Carrega ou recarrega a blocklist do arquivo (troca atômica)."""
        novos_dominios = set()
        if not os.path.exists(self.caminho):
            logging.warning("Blocklist não encontrada: %s", self.caminho)
            self.dominios = novos_dominios
            self.total = 0
            return

        with open(self.caminho, "r", encoding="utf-8", errors="ignore") as f:
            for linha in f:
                match = self.padrao.search(linha.strip())
                if match:
                    novos_dominios.add(match.group(1).lower())

        # Troca atômica: o set antigo nunca fica vazio durante a recarga
        self.dominios = novos_dominios
        self.total = len(self.dominios)
        logging.info("Blocklist carregada: %d domínios", self.total)

    def _carregar_whitelist(self):
        """Carrega a whitelist do arquivo."""
        self.whitelist = set()
        if self.whitelist_path and os.path.exists(self.whitelist_path):
            with open(self.whitelist_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        self.whitelist.add(line)
            logging.info("Whitelist carregada: %d domínios", len(self.whitelist))

    def esta_na_whitelist(self, dominio):
        """Verifica se um domínio está na whitelist."""
        dominio = dominio.lower().rstrip(".")
        if dominio in self.whitelist:
            return True
        # Verifica subdomínios na whitelist
        partes = dominio.split(".")
        for i in range(1, len(partes) - 1):
            pai = ".".join(partes[i:])
            if pai in self.whitelist:
                return True
        return False

    def esta_bloqueado(self, dominio):
        """
        Verifica se um domínio está na blocklist.
        Também verifica subdomínios (ex: sub.ads.com → ads.com).
        """
        dominio = dominio.lower().rstrip(".")
        if dominio in self.dominios:
            return True
        # Verifica domínios pai (bloqueia subdomínios do domínio bloqueado)
        partes = dominio.split(".")
        for i in range(1, len(partes) - 1):
            pai = ".".join(partes[i:])
            if pai in self.dominios:
                return True
        return False

    def recarregar(self):
        """Recarrega a blocklist e whitelist em tempo real (sem reiniciar o servidor)."""
        old = self.total
        self.carregar()
        self._carregar_whitelist()
        diff = self.total - old
        logging.info("Blocklist atualizada: +%d domínios (total: %d, whitelist: %d)",
                     diff, self.total, len(self.whitelist))


# =============================================================================
# DNS Request Handler
# =============================================================================
class DNSHandler:
    """
    Processa requisições DNS individuais.
    - Bloqueia domínios da blocklist
    - Encaminha os demais para upstream DNS
    """

    def __init__(self, blocklist, logger=None, cname_uncloak=True):
        self.blocklist = blocklist
        self.logger = logger or logging.getLogger(__name__)
        self.cname_uncloak = cname_uncloak
        # Sockets são criados sob demanda em cada chamada para evitar
        # race conditions com respostas UDP atrasadas

    def processar(self, data, addr):
        """
        Processa um pacote DNS recebido.

        Args:
            data: bytes — pacote DNS bruto
            addr: tuple — (ip, porta) do cliente

        Returns:
            bytes or None — resposta DNS ou None se for encaminhado
        """
        try:
            request = DNSRecord.parse(data)
        except Exception as e:
            self.logger.error("Erro ao decodificar consulta: %s", e)
            return None

        # Extrair domínio da primeira pergunta
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE.get(request.q.qtype, f"TYPE{request.q.qtype}")

        self.logger.info(
            "query[%s] %s from %s:%s",
            qtype, qname, addr[0], addr[1]
        )

        # Estatísticas por cliente
        ip_cliente = addr[0]
        ESTATISTICAS_CLIENTES[ip_cliente] = ESTATISTICAS_CLIENTES.get(ip_cliente, 0) + 1

        # Verificar whitelist PRIMEIRO — domínios na whitelist nunca são bloqueados
        if self.blocklist.esta_na_whitelist(qname):
            return self._encaminhar_upstream(request, qname, qtype)

        # Verificar blocklist
        if self.blocklist.esta_bloqueado(qname):
            return self._resposta_bloqueio(request, qname, qtype)

        # CNAME Uncloaking: resolve cadeia CNAME para detectar trackers disfarçados
        if self.cname_uncloak and qtype in ("A", "AAAA"):
            destino_cname = self._resolver_cadeia_cname(qname)
            if destino_cname and destino_cname != qname:
                if self.blocklist.esta_bloqueado(destino_cname):
                    self.logger.info(
                        "  🛡️ CNAME-BLOQUEADO: %s → %s [na blocklist]",
                        qname, destino_cname
                    )
                    return self._resposta_bloqueio(request, qname, qtype)
                self.logger.info(
                    "  🟢 CNAME-LIBERADO: %s → %s [não na blocklist]",
                    qname, destino_cname
                )

        # Encaminhar para upstream
        return self._encaminhar_upstream(request, qname, qtype)

    def _resposta_bloqueio(self, request, qname, qtype):
        """
        Gera resposta de bloqueio (0.0.0.0 para A, :: para AAAA).
        """
        reply = request.reply()

        if qtype == "A":
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=300))
        elif qtype == "AAAA":
            reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=300))
        else:
            # Para outros tipos, retorna NXDOMAIN
            reply.header.rcode = RCODE.NXDOMAIN

        self.logger.info("  🛡️ BLOQUEADO: %s [%s]", qname, qtype)
        return reply.pack()

    def _encaminhar_upstream(self, request, qname, qtype):
        """
        Encaminha a consulta para um servidor DNS upstream.
        Tenta cada upstream em ordem até obter resposta.
        Cria um socket novo por tentativa para evitar respostas atrasadas.
        """
        dados_originais = request.pack()

        for upstream_addr in UPSTREAM_DNS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(TIMEOUT_UPSTREAM)
                sock.sendto(dados_originais, upstream_addr)
                resposta, _ = sock.recvfrom(4096)
                sock.close()
                self.logger.info("  ✅ LIBERADO: %s via %s:%d", qname, *upstream_addr)
                return resposta
            except socket.timeout:
                self.logger.warning("  ⏰ TIMEOUT: %s via %s:%d", qname, *upstream_addr)
                try:
                    sock.close()
                except Exception:
                    pass
                continue
            except Exception as e:
                self.logger.error("  ❌ ERRO upstream %s:%d — %s", *upstream_addr, e)
                try:
                    sock.close()
                except Exception:
                    pass
                continue

        # Todos os upstreams falharam → retorna SERVFAIL
        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        self.logger.error("  ❌ TODOS UPSTREAMS FALHARAM: %s", qname)
        return reply.pack()

    def _resolver_cadeia_cname(self, dominio, profundidade=5):
        """
        Resolve a cadeia CNAME de um domínio recursivamente.
        
        Muitos trackers modernos usam CNAMEs para esconder o verdadeiro
        destino (ex: analytics.banco.com CNAME → tracker.ads-service.com).
        Este método descobre essas cadeias.
        
        Args:
            dominio: str — domínio para resolver
            profundidade: int — max recursion depth (evita loops)
        
        Returns:
            str or None — último domínio na cadeia CNAME, ou None se falhar
        """
        if profundidade <= 0:
            return None
        
        try:
            from dnslib import DNSRecord, QTYPE
            
            # Construir consulta CNAME usando DNSRecord.question() (correto)
            q = DNSRecord.question(dominio, qtype=QTYPE.CNAME)
            dados = q.pack()
            
            for upstream_addr in UPSTREAM_DNS:
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(TIMEOUT_UPSTREAM)
                    sock.sendto(dados, upstream_addr)
                    resposta_bytes, _ = sock.recvfrom(4096)
                    
                    resposta = DNSRecord.parse(resposta_bytes)
                    
                    # Extrair CNAME da resposta
                    for rr in resposta.rr:
                        if rr.rtype == QTYPE.CNAME:
                            destino = str(rr.rdata).rstrip(".")
                            if destino != dominio:
                                return self._resolver_cadeia_cname(destino, profundidade - 1) or destino
                    
                    # Se tem A/AAAA record, é terminal (sem CNAME)
                    for rr in resposta.rr:
                        if rr.rtype in (QTYPE.A, QTYPE.AAAA):
                            return dominio
                    
                    # Se não tem CNAME, é terminal
                    return None
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.debug("Erro CNAME %s via %s: %s", dominio, upstream_addr, e)
                    continue
                finally:
                    if sock:
                        try:
                            sock.close()
                        except Exception:
                            pass
            
        except Exception as e:
            self.logger.debug("Erro ao resolver CNAME %s: %s", dominio, e)
        
        return None

    def fechar(self):
        """Não há sockets persistentes para liberar (criados sob demanda)."""
        pass


# =============================================================================
# DNS Server (UDP)
# =============================================================================
class DNSServer:
    """
    Servidor DNS UDP que escuta em uma porta e delega
    o processamento para um DNSHandler.
    Suporta recarga de blocklist via sinal SIGHUP.
    """

    def __init__(self, host="127.0.0.1", port=PORTA_PADRAO, blocklist_path=BLOCKLIST_PATH, cname_uncloak=None):
        self.host = host
        self.port = port
        self.cname_uncloak = cname_uncloak if cname_uncloak is not None else CNAME_UNCLOAK
        self.blocklist = BlocklistManager(blocklist_path, whitelist_path=WHITELIST_PATH)
        self.handler = DNSHandler(self.blocklist, cname_uncloak=self.cname_uncloak)
        self.sock = None
        self.rodando = False

    def iniciar(self):
        """Inicia o servidor DNS."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.settimeout(1.0)  # timeout para verificar self.rodando
        self.rodando = True

        # Registrar handlers de sinal
        signal.signal(signal.SIGTERM, self._sinal_parar)
        signal.signal(signal.SIGINT, self._sinal_parar)
        signal.signal(signal.SIGHUP, self._sinal_recarregar)

        logging.info(
            "Servidor DNS iniciado em %s:%s",
            self.host, self.port
        )
        logging.info("CNAME Uncloaking: %s", "ATIVADO 🛡️" if self.cname_uncloak else "desligado")
        logging.info("Domínios na blocklist: %d", self.blocklist.total)
        logging.info("Upstreams: %s", UPSTREAM_DNS)

        self._loop_principal()

    def _loop_principal(self):
        """Loop principal de recebimento e processamento de pacotes."""
        while self.rodando:
            try:
                data, addr = self.sock.recvfrom(4096)
                resposta = self.handler.processar(data, addr)
                if resposta:
                    self.sock.sendto(resposta, addr)
            except socket.timeout:
                continue
            except OSError as e:
                if self.rodando:
                    logging.error("Erro no socket: %s", e)
                    break
            except Exception as e:
                logging.error("Erro inesperado: %s", e)

        self._parar()

    def _parar(self):
        """Para o servidor e libera recursos."""
        self.rodando = False
        self.handler.fechar()
        if self.sock:
            self.sock.close()
        logging.info("Servidor DNS parado.")

    def _sinal_parar(self, signum, frame):
        """Handler para sinais SIGTERM/SIGINT."""
        logging.info("Recebido sinal %s. Parando...", signum)
        self.rodando = False

    def _sinal_recarregar(self, signum, frame):
        """Handler para SIGHUP — recarrega a blocklist em tempo real."""
        logging.info("Recebido SIGHUP. Recarregando blocklist...")
        self.blocklist.recarregar()

    def recarregar_blocklist(self):
        """Recarrega a blocklist em tempo real."""
        logging.info("Recarregando blocklist por solicitação...")
        self.blocklist.recarregar()


# =============================================================================
# Utilitários CLI
# =============================================================================
def escrever_pid():
    """Salva o PID do processo atual no arquivo PID."""
    with open(PID_PATH, "w") as f:
        f.write(str(os.getpid()))


def remover_pid():
    """Remove o arquivo PID."""
    if os.path.exists(PID_PATH):
        os.remove(PID_PATH)


def configurar_logging(modo_verbose=False):
    """Configura o sistema de logging para arquivo e opcionalmente terminal."""
    level = logging.DEBUG if modo_verbose else logging.INFO

    # Remove handlers existentes para evitar duplicação em restart
    root = logging.getLogger()
    for handler in root.handlers[:]:
        root.removeHandler(handler)
        handler.close()

    # Handler para arquivo
    file_handler = logging.FileHandler(LOG_PATH)
    file_handler.setLevel(level)
    file_formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s",
        datefmt="%b %d %H:%M:%S"
    )
    file_handler.setFormatter(file_formatter)

    # Handler para terminal
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_formatter = logging.Formatter("%(levelname)s: %(message)s")
    console_handler.setFormatter(console_formatter)

    # Configurar root logger
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(file_handler)
    root.addHandler(console_handler)


# =============================================================================
# Ponto de Entrada
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="TermuxNetShield — Servidor DNS Bloqueador de Anúncios"
    )
    parser.add_argument(
        "--port", type=int, default=PORTA_PADRAO,
        help=f"Porta para escutar (padrão: {PORTA_PADRAO})"
    )
    parser.add_argument(
        "--host", type=str, default="127.0.0.1",
        help="Host para escutar (padrão: 127.0.0.1)"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Modo verbose (logs mais detalhados)"
    )
    parser.add_argument(
        "--reload", action="store_true",
        help="Recarregar blocklist de um servidor em execução"
    )
    parser.add_argument(
        "--cname-uncloak", default=None, action="store_true",
        help="Ativar CNAME uncloaking (padrão: True)"
    )
    parser.add_argument(
        "--no-cname-uncloak", dest="cname_uncloak", action="store_false",
        help="Desativar CNAME uncloaking"
    )

    args = parser.parse_args()

    # ── Modo reload: envia SIGHUP para servidor em execução ──
    if args.reload:
        if not os.path.exists(PID_PATH):
            print("ERRO: PID file não encontrado. O servidor não está rodando?")
            sys.exit(1)
        with open(PID_PATH) as f:
            pid = int(f.read().strip())
        try:
            os.kill(pid, signal.SIGHUP)
            print(f"Sinal SIGHUP enviado para PID {pid}. Blocklist recarregada.")
            sys.exit(0)
        except ProcessLookupError:
            print(f"ERRO: Processo PID {pid} não encontrado.")
            sys.exit(1)
        except PermissionError:
            print(f"ERRO: Permissão negada para enviar sinal ao PID {pid}.")
            sys.exit(1)

    # Configurar logging
    configurar_logging(args.verbose)

    # Escrever PID
    escrever_pid()

    logging.info("=" * 50)
    logging.info("TermuxNetShield v1.0 — Iniciando")
    logging.info("=" * 50)

    try:
        server = DNSServer(host=args.host, port=args.port, cname_uncloak=args.cname_uncloak)
        server.iniciar()
    except PermissionError:
        logging.error(
            "Permissão negada para porta %s. "
            "Use porta >= 1024 (padrão: %s).",
            args.port, PORTA_PADRAO
        )
        sys.exit(1)
    except OSError as e:
        logging.error("Erro de rede: %s", e)
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("Interrompido pelo usuário.")
    finally:
        remover_pid()

    logging.info("Servidor encerrado.")


if __name__ == "__main__":
    main()
