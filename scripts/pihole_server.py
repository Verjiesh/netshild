#!/usr/bin/env python3
"""
TermuxNetShield — Pi-hole Style DNS Server
==========================================
Servidor DNS local com interface web estilo Pi-hole para bloqueio de anúncios.

Funcionalidades:
  - Servidor DNS na porta 5353 (UDP)
  - Interface web na porta 8080 com dashboard
  - API REST para consultas e configurações
  - Estatísticas em tempo real (consultas, bloqueios, clientes)
  - Gráficos de uso (top domínios, top clientes, tipos de consulta)
  - Ativação/desativação do bloqueio via interface
  - Adição de domínios à whitelist/blacklist via interface
  - Logs detalhados com busca e filtros
  - Suporte a múltiplas blocklists
  - CNAME uncloaking para detectar trackers disfarçados

Dependências: pip install dnslib aiohttp aiofiles psutil rich click
"""

import os
import re
import sys
import json
import signal
import socket
import logging
import argparse
import threading
import asyncio
from collections import OrderedDict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

try:
    from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, AAAA, CNAME, RCODE
except ImportError:
    print("ERRO: Biblioteca 'dnslib' não instalada.")
    print("Execute: pip install dnslib")
    sys.exit(1)

try:
    from aiohttp import web
except ImportError:
    print("ERRO: Biblioteca 'aiohttp' não instalada.")
    print("Execute: pip install aiohttp")
    sys.exit(1)


# ─── Diretórios e arquivos ───────────────────────────────────────────────────
HOME = os.path.expanduser("~")
PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLOCKLIST_PATH = os.path.join(PROJETO, "blocklists", "ads.conf")
WHITELIST_PATH = os.path.join(PROJETO, "config", "whitelist.txt")
BLACKLIST_PATH = os.path.join(PROJETO, "config", "blacklist.txt")
LOG_PATH = os.path.join(PROJETO, "logs", "dns_server.log")
QUERY_LOG_PATH = os.path.join(PROJETO, "logs", "queries.log")
PID_PATH = os.path.join(PROJETO, "logs", "dns_server.pid")
STATS_PATH = os.path.join(PROJETO, "logs", "stats.json")

os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
os.makedirs(os.path.join(PROJETO, "config"), exist_ok=True)

# ─── Configurações padrão ───────────────────────────────────────────────────
PORTA_DNS = 5353
PORTA_WEB = 8080
UPSTREAM_DNS = [
    ("1.1.1.1", 53),
    ("1.0.0.1", 53),
    ("8.8.8.8", 53),
]
TIMEOUT_UPSTREAM = 2.0
CNAME_UNCLOAK = True

# Limites para evitar vazamento de memória
MAX_CLIENTES_ESTASTICAS = 1000
MAX_LOG_ENTRIES = 10000
MAX_QUERY_LOG_ENTRIES = 50000

# Estado global thread-safe
ESTATISTICAS_LOCK = threading.Lock()
ESTATISTICAS_CLIENTES: OrderedDict[str, int] = OrderedDict()
BLOQUEIO_ATIVO = True
TOTAL_QUERIES = 0
TOTAL_BLOQUEADOS = 0
TOTAL_PERMITIDOS = 0
TIPOS_QUERY: Counter[str] = Counter()
DOMINIOS_TOP: Counter[str] = Counter()
CLIENTES_TOP: Counter[str] = Counter()
HORA_INICIO = datetime.now()

# Log de queries em memória (circular buffer)
QUERY_LOG_LOCK = threading.Lock()
QUERY_LOG: List[Dict[str, Any]] = []


# =============================================================================
# Blocklist Manager
# =============================================================================
class BlocklistManager:
    """Gerencia listas de bloqueio, whitelist e blacklist."""

    def __init__(self, blocklist_path: str, whitelist_path: str = None, blacklist_path: str = None):
        self.blocklist_path = blocklist_path
        self.whitelist_path = whitelist_path
        self.blacklist_path = blacklist_path
        self.dominios: set = set()
        self.whitelist: set = set()
        self.blacklist: set = set()
        self.padrao = re.compile(r"address=/([^/]+)/")
        self.total = 0
        self.carregar()
        self._carregar_whitelist()
        self._carregar_blacklist()

    def carregar(self):
        """Carrega ou recarrega a blocklist principal."""
        novos_dominios = set()
        if not os.path.exists(self.blocklist_path):
            logging.warning("Blocklist não encontrada: %s", self.blocklist_path)
            self.dominios = novos_dominios
            self.total = 0
            return

        with open(self.blocklist_path, "r", encoding="utf-8", errors="ignore") as f:
            for linha in f:
                match = self.padrao.search(linha.strip())
                if match:
                    novos_dominios.add(match.group(1).lower())

        self.dominios = novos_dominios
        self.total = len(self.dominios)
        logging.info("Blocklist carregada: %d domínios", self.total)

    def _carregar_whitelist(self):
        """Carrega a whitelist."""
        self.whitelist = set()
        if self.whitelist_path and os.path.exists(self.whitelist_path):
            with open(self.whitelist_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        self.whitelist.add(line)
            logging.info("Whitelist carregada: %d domínios", len(self.whitelist))

    def _carregar_blacklist(self):
        """Carrega a blacklist adicional."""
        self.blacklist = set()
        if self.blacklist_path and os.path.exists(self.blacklist_path):
            with open(self.blacklist_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        self.blacklist.add(line)
            logging.info("Blacklist carregada: %d domínios", len(self.blacklist))

    def esta_na_whitelist(self, dominio: str) -> bool:
        """Verifica se domínio está na whitelist."""
        dominio = dominio.lower().rstrip(".")
        if dominio in self.whitelist:
            return True
        partes = dominio.split(".")
        for i in range(1, len(partes) - 1):
            pai = ".".join(partes[i:])
            if pai in self.whitelist:
                return True
        return False

    def esta_na_blacklist(self, dominio: str) -> bool:
        """Verifica se domínio está na blacklist."""
        dominio = dominio.lower().rstrip(".")
        if dominio in self.blacklist:
            return True
        partes = dominio.split(".")
        for i in range(1, len(partes) - 1):
            pai = ".".join(partes[i:])
            if pai in self.blacklist:
                return True
        return False

    def esta_bloqueado(self, dominio: str) -> bool:
        """Verifica se domínio deve ser bloqueado."""
        dominio = dominio.lower().rstrip(".")
        
        # Blacklist tem prioridade máxima
        if self.esta_na_blacklist(dominio):
            return True
        
        # Verifica blocklist principal
        if dominio in self.dominios:
            return True
        
        # Verifica domínios pai
        partes = dominio.split(".")
        for i in range(1, len(partes) - 1):
            pai = ".".join(partes[i:])
            if pai in self.dominios or pai in self.blacklist:
                return True
        
        return False

    def adicionar_a_whitelist(self, dominio: str):
        """Adiciona domínio à whitelist."""
        dominio = dominio.lower().rstrip(".")
        self.whitelist.add(dominio)
        if self.whitelist_path:
            with open(self.whitelist_path, "a", encoding="utf-8") as f:
                f.write(f"{dominio}\n")
        logging.info("Domínio adicionado à whitelist: %s", dominio)

    def adicionar_a_blacklist(self, dominio: str):
        """Adiciona domínio à blacklist."""
        dominio = dominio.lower().rstrip(".")
        self.blacklist.add(dominio)
        if self.blacklist_path:
            with open(self.blacklist_path, "a", encoding="utf-8") as f:
                f.write(f"{dominio}\n")
        logging.info("Domínio adicionado à blacklist: %s", dominio)

    def remover_da_whitelist(self, dominio: str):
        """Remove domínio da whitelist."""
        dominio = dominio.lower().rstrip(".")
        self.whitelist.discard(dominio)
        if self.whitelist_path and os.path.exists(self.whitelist_path):
            with open(self.whitelist_path, "r", encoding="utf-8") as f:
                linhas = f.readlines()
            with open(self.whitelist_path, "w", encoding="utf-8") as f:
                for linha in linhas:
                    if linha.strip().lower() != dominio:
                        f.write(linha)
        logging.info("Domínio removido da whitelist: %s", dominio)

    def remover_da_blacklist(self, dominio: str):
        """Remove domínio da blacklist."""
        dominio = dominio.lower().rstrip(".")
        self.blacklist.discard(dominio)
        if self.blacklist_path and os.path.exists(self.blacklist_path):
            with open(self.blacklist_path, "r", encoding="utf-8") as f:
                linhas = f.readlines()
            with open(self.blacklist_path, "w", encoding="utf-8") as f:
                for linha in linhas:
                    if linha.strip().lower() != dominio:
                        f.write(linha)
        logging.info("Domínio removido da blacklist: %s", dominio)

    def recarregar(self):
        """Recarrega todas as listas."""
        old = self.total
        self.carregar()
        self._carregar_whitelist()
        self._carregar_blacklist()
        diff = self.total - old
        logging.info(
            "Listas atualizadas: +%d blocklist, %d whitelist, %d blacklist",
            diff, len(self.whitelist), len(self.blacklist)
        )


# =============================================================================
# DNS Request Handler
# =============================================================================
class DNSHandler:
    """Processa requisições DNS individuais."""

    def __init__(self, blocklist: BlocklistManager, logger=None, cname_uncloak: bool = True):
        self.blocklist = blocklist
        self.logger = logger or logging.getLogger(__name__)
        self.cname_uncloak = cname_uncloak

    def processar(self, data: bytes, addr: Tuple[str, int]) -> Optional[bytes]:
        """Processa um pacote DNS recebido."""
        global TOTAL_QUERIES, TOTAL_BLOQUEADOS, TOTAL_PERMITIDOS
        
        try:
            request = DNSRecord.parse(data)
        except Exception as e:
            self.logger.error("Erro ao decodificar consulta: %s", e)
            return None

        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE.get(request.q.qtype, f"TYPE{request.q.qtype}")
        ip_cliente = addr[0]

        # Atualizar estatísticas globais
        with ESTATISTICAS_LOCK:
            TOTAL_QUERIES += 1
            TIPOS_QUERY[qtype] += 1
            DOMINIOS_TOP[qname] += 1
            CLIENTES_TOP[ip_cliente] += 1
            
            # LRU para clientes
            if ip_cliente in ESTATISTICAS_CLIENTES:
                ESTATISTICAS_CLIENTES.move_to_end(ip_cliente)
                ESTATISTICAS_CLIENTES[ip_cliente] += 1
            else:
                if len(ESTATISTICAS_CLIENTES) >= MAX_CLIENTES_ESTASTICAS:
                    ESTATISTICAS_CLIENTES.popitem(last=False)
                ESTATISTICAS_CLIENTES[ip_cliente] = 1

        self.logger.info("query[%s] %s from %s:%s", qtype, qname, ip_cliente, addr[1])

        # Registrar query no log
        self._registrar_query(qname, qtype, ip_cliente, "PROCESSANDO")

        # Verificar se bloqueio está ativo
        if not BLOQUEIO_ATIVO:
            self._registrar_query(qname, qtype, ip_cliente, "PERMITIDO", motivo="Bloqueio desativado")
            with ESTATISTICAS_LOCK:
                TOTAL_PERMITIDOS += 1
            return self._encaminhar_upstream(request, qname, qtype)

        # Verificar whitelist
        if self.blocklist.esta_na_whitelist(qname):
            self._registrar_query(qname, qtype, ip_cliente, "PERMITIDO", motivo="Whitelist")
            with ESTATISTICAS_LOCK:
                TOTAL_PERMITIDOS += 1
            return self._encaminhar_upstream(request, qname, qtype)

        # Verificar blocklist/blacklist
        if self.blocklist.esta_bloqueado(qname):
            self._registrar_query(qname, qtype, ip_cliente, "BLOQUEADO", motivo="Blocklist")
            with ESTATISTICAS_LOCK:
                TOTAL_BLOQUEADOS += 1
            return self._resposta_bloqueio(request, qname, qtype)

        # CNAME Uncloaking
        if self.cname_uncloak and qtype in ("A", "AAAA"):
            destino_cname = self._resolver_cadeia_cname(qname)
            if destino_cname and destino_cname != qname:
                if self.blocklist.esta_bloqueado(destino_cname):
                    self._registrar_query(
                        qname, qtype, ip_cliente, "BLOQUEADO",
                        motivo=f"CNAME: {destino_cname}"
                    )
                    with ESTATISTICAS_LOCK:
                        TOTAL_BLOQUEADOS += 1
                    self.logger.info("🛡️ CNAME-BLOQUEADO: %s → %s", qname, destino_cname)
                    return self._resposta_bloqueio(request, qname, qtype)
                self.logger.info("🟢 CNAME-LIBERADO: %s → %s", qname, destino_cname)

        # Encaminhar para upstream
        self._registrar_query(qname, qtype, ip_cliente, "PERMITIDO")
        with ESTATISTICAS_LOCK:
            TOTAL_PERMITIDOS += 1
        return self._encaminhar_upstream(request, qname, qtype)

    def _registrar_query(self, dominio: str, tipo: str, cliente: str, status: str, motivo: str = ""):
        """Registra query no log circular."""
        entrada = {
            "timestamp": datetime.now().isoformat(),
            "dominio": dominio,
            "tipo": tipo,
            "cliente": cliente,
            "status": status,
            "motivo": motivo
        }
        
        with QUERY_LOG_LOCK:
            QUERY_LOG.append(entrada)
            # Manter apenas últimas entradas
            if len(QUERY_LOG) > MAX_QUERY_LOG_ENTRIES:
                QUERY_LOG.pop(0)

    def _resposta_bloqueio(self, request: DNSRecord, qname: str, qtype: str) -> bytes:
        """Gera resposta de bloqueio."""
        reply = request.reply()

        if qtype == "A":
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=300))
        elif qtype == "AAAA":
            reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=300))
        else:
            reply.header.rcode = RCODE.NXDOMAIN

        self.logger.info("🛡️ BLOQUEADO: %s [%s]", qname, qtype)
        return reply.pack()

    def _encaminhar_upstream(self, request: DNSRecord, qname: str, qtype: str) -> Optional[bytes]:
        """Encaminha consulta para upstream DNS."""
        dados_originais = request.pack()

        for upstream_addr in UPSTREAM_DNS:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(TIMEOUT_UPSTREAM)
                sock.sendto(dados_originais, upstream_addr)
                resposta, _ = sock.recvfrom(4096)
                self.logger.info("✅ LIBERADO: %s via %s:%d", qname, *upstream_addr)
                return resposta
            except socket.timeout:
                self.logger.warning("⏰ TIMEOUT: %s via %s:%d", qname, *upstream_addr)
                continue
            except Exception as e:
                self.logger.error("❌ ERRO upstream %s:%d — %s", *upstream_addr, e)
                continue
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass

        # Todos falharam
        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        self.logger.error("❌ TODOS UPSTREAMS FALHARAM: %s", qname)
        return reply.pack()

    def _resolver_cadeia_cname(self, dominio: str, profundidade: int = 5) -> Optional[str]:
        """Resolve cadeia CNAME recursivamente."""
        if profundidade <= 0:
            return None
        
        try:
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
                    
                    for rr in resposta.rr:
                        if rr.rtype == QTYPE.CNAME:
                            destino = str(rr.rdata).rstrip(".")
                            if destino != dominio:
                                return self._resolver_cadeia_cname(destino, profundidade - 1) or destino
                    
                    for rr in resposta.rr:
                        if rr.rtype in (QTYPE.A, QTYPE.AAAA):
                            return dominio
                    
                    return None
                    
                except socket.timeout:
                    continue
                except Exception:
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
        """Libera recursos (nenhum socket persistente)."""
        pass


# =============================================================================
# DNS Server (UDP)
# =============================================================================
class DNSServer:
    """Servidor DNS UDP com suporte a recarga via SIGHUP."""

    def __init__(self, host: str = "127.0.0.1", port: int = PORTA_DNS, 
                 blocklist_path: str = BLOCKLIST_PATH, cname_uncloak: bool = None):
        self.host = host
        self.port = port
        self.cname_uncloak = cname_uncloak if cname_uncloak is not None else CNAME_UNCLOAK
        self.blocklist = BlocklistManager(blocklist_path, WHITELIST_PATH, BLACKLIST_PATH)
        self.handler = DNSHandler(self.blocklist, cname_uncloak=self.cname_uncloak)
        self.sock = None
        self.rodando = False

    def iniciar(self):
        """Inicia o servidor DNS."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.settimeout(1.0)
        self.rodando = True

        # Handlers de sinal só funcionam na thread principal
        # Em threads secundárias, usamos polling do flag self.rodando
        logging.info(
            "Servidor DNS iniciado em %s:%s",
            self.host, self.port
        )
        logging.info("CNAME Uncloaking: %s", "ATIVADO 🛡️" if self.cname_uncloak else "desligado")
        logging.info("Domínios na blocklist: %d", self.blocklist.total)
        logging.info("Upstreams: %s", UPSTREAM_DNS)

        self._loop_principal()

    def _loop_principal(self):
        """Loop principal de recebimento."""
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
        """Para o servidor."""
        self.rodando = False
        self.handler.fechar()
        if self.sock:
            self.sock.close()
        logging.info("Servidor DNS parado.")

    def _sinal_parar(self, signum, frame):
        """Handler SIGTERM/SIGINT."""
        logging.info("Recebido sinal %s. Parando...", signum)
        self.rodando = False

    def _sinal_recarregar(self, signum, frame):
        """Handler SIGHUP."""
        logging.info("Recebido SIGHUP. Recarregando blocklist...")
        self.blocklist.recarregar()

    def recarregar_blocklist(self):
        """Recarrega blocklist manualmente."""
        self.blocklist.recarregar()


# =============================================================================
# Web Interface (Pi-hole Style)
# =============================================================================
class WebInterface:
    """Interface web estilo Pi-hole com dashboard e API REST."""

    def __init__(self, dns_server: DNSServer, host: str = "0.0.0.0", port: int = PORTA_WEB):
        self.dns_server = dns_server
        self.host = host
        self.port = port
        self.app = web.Application()
        self._setup_routes()

    def _setup_routes(self):
        """Configura rotas da API e interface web."""
        self.app.router.add_get("/", self._dashboard_html)
        self.app.router.add_get("/api/stats", self._api_stats)
        self.app.router.add_get("/api/queries", self._api_queries)
        self.app.router.add_get("/api/top-domains", self._api_top_domains)
        self.app.router.add_get("/api/top-clients", self._api_top_clients)
        self.app.router.add_get("/api/querytypes", self._api_querytypes)
        self.app.router.add_get("/api/blocklist/status", self._api_blocklist_status)
        self.app.router.add_post("/api/blocklist/enable", self._api_enable_blocking)
        self.app.router.add_post("/api/blocklist/disable", self._api_disable_blocking)
        self.app.router.add_post("/api/whitelist/add", self._api_add_whitelist)
        self.app.router.add_post("/api/whitelist/remove", self._api_remove_whitelist)
        self.app.router.add_post("/api/blacklist/add", self._api_add_blacklist)
        self.app.router.add_post("/api/blacklist/remove", self._api_remove_blacklist)
        self.app.router.add_post("/api/blocklist/reload", self._api_reload_blocklist)
        # Static files (opcional)
        static_path = os.path.join(PROJETO, "static")
        if os.path.exists(static_path):
            self.app.router.add_static("/static", path=static_path)

    async def _dashboard_html(self, request: web.Request) -> web.Response:
        """Retorna dashboard HTML."""
        html = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TermuxNetShield - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; color: #2d3436; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2rem; text-align: center; }
        .header h1 { font-size: 2rem; margin-bottom: 0.5rem; }
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .stat-card { background: white; border-radius: 10px; padding: 1.5rem; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-card h3 { color: #636e72; font-size: 0.9rem; margin-bottom: 0.5rem; }
        .stat-card .value { font-size: 2.5rem; font-weight: bold; color: #2d3436; }
        .stat-card.blocked .value { color: #e74c3c; }
        .stat-card.allowed .value { color: #27ae60; }
        .controls { background: white; border-radius: 10px; padding: 1.5rem; margin-bottom: 2rem; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .btn { padding: 0.75rem 1.5rem; border: none; border-radius: 5px; cursor: pointer; font-size: 1rem; margin-right: 0.5rem; transition: all 0.3s; }
        .btn-primary { background: #667eea; color: white; }
        .btn-primary:hover { background: #5568d3; }
        .btn-danger { background: #e74c3c; color: white; }
        .btn-danger:hover { background: #c0392b; }
        .btn-success { background: #27ae60; color: white; }
        .btn-success:hover { background: #219a52; }
        .section { background: white; border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section h2 { margin-bottom: 1rem; color: #2d3436; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #dfe6e9; }
        th { background: #f8f9fa; font-weight: 600; }
        tr:hover { background: #f8f9fa; }
        .status-badge { padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.85rem; font-weight: 600; }
        .status-active { background: #d4edda; color: #155724; }
        .status-disabled { background: #f8d7da; color: #721c24; }
        input[type="text"] { padding: 0.75rem; border: 1px solid #dfe6e9; border-radius: 5px; width: 300px; margin-right: 0.5rem; }
        .form-group { margin-bottom: 1rem; }
        .loading { text-align: center; padding: 2rem; color: #636e72; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ TermuxNetShield</h1>
        <p>Network-wide Ad Blocking - Pi-hole Style</p>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Queries</h3>
                <div class="value" id="total-queries">-</div>
            </div>
            <div class="stat-card blocked">
                <h3>Queries Blocked</h3>
                <div class="value" id="total-blocked">-</div>
            </div>
            <div class="stat-card allowed">
                <h3>Queries Allowed</h3>
                <div class="value" id="total-allowed">-</div>
            </div>
            <div class="stat-card">
                <h3>Blocklist Size</h3>
                <div class="value" id="blocklist-size">-</div>
            </div>
        </div>

        <div class="controls">
            <h2>Controls</h2>
            <div style="margin-top: 1rem;">
                <span id="blocking-status" class="status-badge status-active">Blocking Active</span>
                <button class="btn btn-danger" onclick="disableBlocking()" style="margin-left: 1rem;">Disable Blocking</button>
                <button class="btn btn-success" onclick="enableBlocking()">Enable Blocking</button>
                <button class="btn btn-primary" onclick="reloadBlocklist()">Reload Blocklist</button>
            </div>
        </div>

        <div class="section">
            <h2>Add to Lists</h2>
            <div class="form-group">
                <input type="text" id="domain-input" placeholder="example.com">
                <button class="btn btn-danger" onclick="addToBlacklist()">Add to Blacklist</button>
                <button class="btn btn-success" onclick="addToWhitelist()">Add to Whitelist</button>
            </div>
        </div>

        <div class="section">
            <h2>Top Domains</h2>
            <table>
                <thead>
                    <tr><th>Domain</th><th>Count</th></tr>
                </thead>
                <tbody id="top-domains">
                    <tr><td colspan="2" class="loading">Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Top Clients</h2>
            <table>
                <thead>
                    <tr><th>Client IP</th><th>Count</th></tr>
                </thead>
                <tbody id="top-clients">
                    <tr><td colspan="2" class="loading">Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Recent Queries</h2>
            <table>
                <thead>
                    <tr><th>Time</th><th>Domain</th><th>Type</th><th>Client</th><th>Status</th></tr>
                </thead>
                <tbody id="recent-queries">
                    <tr><td colspan="5" class="loading">Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        async function fetchStats() {
            const resp = await fetch('/api/stats');
            const data = await resp.json();
            document.getElementById('total-queries').textContent = data.total_queries.toLocaleString();
            document.getElementById('total-blocked').textContent = data.total_blocked.toLocaleString();
            document.getElementById('total-allowed').textContent = data.total_allowed.toLocaleString();
            document.getElementById('blocklist-size').textContent = data.blocklist_total.toLocaleString();
            
            const statusEl = document.getElementById('blocking-status');
            if (data.blocking_active) {
                statusEl.textContent = 'Blocking Active';
                statusEl.className = 'status-badge status-active';
            } else {
                statusEl.textContent = 'Blocking Disabled';
                statusEl.className = 'status-badge status-disabled';
            }
        }

        async function fetchTopDomains() {
            const resp = await fetch('/api/top-domains');
            const data = await resp.json();
            const tbody = document.getElementById('top-domains');
            tbody.innerHTML = data.top_domains.slice(0, 10).map(([domain, count]) => 
                `<tr><td>${domain}</td><td>${count.toLocaleString()}</td></tr>`
            ).join('');
        }

        async function fetchTopClients() {
            const resp = await fetch('/api/top-clients');
            const data = await resp.json();
            const tbody = document.getElementById('top-clients');
            tbody.innerHTML = data.top_clients.slice(0, 10).map(([client, count]) => 
                `<tr><td>${client}</td><td>${count.toLocaleString()}</td></tr>`
            ).join('');
        }

        async function fetchQueries() {
            const resp = await fetch('/api/queries?limit=20');
            const data = await resp.json();
            const tbody = document.getElementById('recent-queries');
            tbody.innerHTML = data.queries.map(q => {
                const time = new Date(q.timestamp).toLocaleTimeString();
                const statusClass = q.status === 'BLOQUEADO' ? 'color: #e74c3c;' : 'color: #27ae60;';
                return `<tr>
                    <td>${time}</td>
                    <td>${q.dominio}</td>
                    <td>${q.tipo}</td>
                    <td>${q.cliente}</td>
                    <td style="${statusClass}"><strong>${q.status}</strong>${q.motivo ? ' (' + q.motivo + ')' : ''}</td>
                </tr>`;
            }).join('');
        }

        async function disableBlocking() {
            await fetch('/api/blocklist/disable', { method: 'POST' });
            fetchStats();
        }

        async function enableBlocking() {
            await fetch('/api/blocklist/enable', { method: 'POST' });
            fetchStats();
        }

        async function reloadBlocklist() {
            await fetch('/api/blocklist/reload', { method: 'POST' });
            alert('Blocklist reloaded!');
            fetchStats();
        }

        async function addToBlacklist() {
            const domain = document.getElementById('domain-input').value.trim();
            if (!domain) return alert('Enter a domain');
            await fetch('/api/blacklist/add', { 
                method: 'POST', 
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({domain})
            });
            document.getElementById('domain-input').value = '';
            alert('Added to blacklist!');
        }

        async function addToWhitelist() {
            const domain = document.getElementById('domain-input').value.trim();
            if (!domain) return alert('Enter a domain');
            await fetch('/api/whitelist/add', { 
                method: 'POST', 
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({domain})
            });
            document.getElementById('domain-input').value = '';
            alert('Added to whitelist!');
        }

        // Auto-refresh
        setInterval(fetchStats, 5000);
        setInterval(fetchTopDomains, 10000);
        setInterval(fetchTopClients, 10000);
        setInterval(fetchQueries, 5000);
        
        // Initial load
        fetchStats();
        fetchTopDomains();
        fetchTopClients();
        fetchQueries();
    </script>
</body>
</html>
        """
        return web.Response(text=html, content_type="text/html")

    async def _api_stats(self, request: web.Request) -> web.Response:
        """API: Estatísticas gerais."""
        with ESTATISTICAS_LOCK:
            uptime = (datetime.now() - HORA_INICIO).total_seconds()
            data = {
                "total_queries": TOTAL_QUERIES,
                "total_blocked": TOTAL_BLOQUEADOS,
                "total_allowed": TOTAL_PERMITIDOS,
                "blocking_active": BLOQUEIO_ATIVO,
                "blocklist_total": self.dns_server.blocklist.total,
                "whitelist_total": len(self.dns_server.blocklist.whitelist),
                "blacklist_total": len(self.dns_server.blocklist.blacklist),
                "uptime_seconds": uptime,
                "clients_count": len(ESTATISTICAS_CLIENTES)
            }
        return web.json_response(data)

    async def _api_queries(self, request: web.Request) -> web.Response:
        """API: Lista de queries recentes."""
        limit = int(request.query.get("limit", 100))
        with QUERY_LOG_LOCK:
            queries = list(reversed(QUERY_LOG[-limit:]))
        return web.json_response({"queries": queries})

    async def _api_top_domains(self, request: web.Request) -> web.Response:
        """API: Top domínios consultados."""
        with ESTATISTICAS_LOCK:
            top = DOMINIOS_TOP.most_common(50)
        return web.json_response({"top_domains": top})

    async def _api_top_clients(self, request: web.Request) -> web.Response:
        """API: Top clientes."""
        with ESTATISTICAS_LOCK:
            top = CLIENTES_TOP.most_common(50)
        return web.json_response({"top_clients": top})

    async def _api_querytypes(self, request: web.Request) -> web.Response:
        """API: Tipos de query."""
        with ESTATISTICAS_LOCK:
            types = dict(TIPOS_QUERY)
        return web.json_response({"query_types": types})

    async def _api_blocklist_status(self, request: web.Request) -> web.Response:
        """API: Status do bloqueio."""
        return web.json_response({
            "blocking_active": BLOQUEIO_ATIVO,
            "blocklist_total": self.dns_server.blocklist.total,
            "whitelist_total": len(self.dns_server.blocklist.whitelist),
            "blacklist_total": len(self.dns_server.blocklist.blacklist)
        })

    async def _api_enable_blocking(self, request: web.Request) -> web.Response:
        """API: Habilitar bloqueio."""
        global BLOQUEIO_ATIVO
        BLOQUEIO_ATIVO = True
        logging.info("Bloqueio habilitado via API")
        return web.json_response({"success": True, "blocking_active": True})

    async def _api_disable_blocking(self, request: web.Request) -> web.Response:
        """API: Desabilitar bloqueio."""
        global BLOQUEIO_ATIVO
        BLOQUEIO_ATIVO = False
        logging.info("Bloqueio desabilitado via API")
        return web.json_response({"success": True, "blocking_active": False})

    async def _api_add_whitelist(self, request: web.Request) -> web.Response:
        """API: Adicionar à whitelist."""
        data = await request.json()
        domain = data.get("domain", "").strip()
        if not domain:
            return web.json_response({"error": "Domain required"}, status=400)
        self.dns_server.blocklist.adicionar_a_whitelist(domain)
        return web.json_response({"success": True, "domain": domain})

    async def _api_remove_whitelist(self, request: web.Request) -> web.Response:
        """API: Remover da whitelist."""
        data = await request.json()
        domain = data.get("domain", "").strip()
        if not domain:
            return web.json_response({"error": "Domain required"}, status=400)
        self.dns_server.blocklist.remover_da_whitelist(domain)
        return web.json_response({"success": True, "domain": domain})

    async def _api_add_blacklist(self, request: web.Request) -> web.Response:
        """API: Adicionar à blacklist."""
        data = await request.json()
        domain = data.get("domain", "").strip()
        if not domain:
            return web.json_response({"error": "Domain required"}, status=400)
        self.dns_server.blocklist.adicionar_a_blacklist(domain)
        return web.json_response({"success": True, "domain": domain})

    async def _api_remove_blacklist(self, request: web.Request) -> web.Response:
        """API: Remover da blacklist."""
        data = await request.json()
        domain = data.get("domain", "").strip()
        if not domain:
            return web.json_response({"error": "Domain required"}, status=400)
        self.dns_server.blocklist.remover_da_blacklist(domain)
        return web.json_response({"success": True, "domain": domain})

    async def _api_reload_blocklist(self, request: web.Request) -> web.Response:
        """API: Recarregar blocklist."""
        self.dns_server.recarregar_blocklist()
        return web.json_response({"success": True})

    async def start(self):
        """Inicia servidor web."""
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        logging.info("Interface web iniciada em http://%s:%d", self.host, self.port)
        return runner


# =============================================================================
# Utilitários CLI
# =============================================================================
def escrever_pid():
    """Salva o PID do processo."""
    with open(PID_PATH, "w") as f:
        f.write(str(os.getpid()))


def remover_pid():
    """Remove arquivo PID."""
    if os.path.exists(PID_PATH):
        os.remove(PID_PATH)


def configurar_logging(modo_verbose: bool = False):
    """Configura logging."""
    level = logging.DEBUG if modo_verbose else logging.INFO
    
    root = logging.getLogger()
    for handler in root.handlers[:]:
        root.removeHandler(handler)
        handler.close()
    
    file_handler = logging.FileHandler(LOG_PATH)
    file_handler.setLevel(level)
    file_formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s",
        datefmt="%b %d %H:%M:%S"
    )
    file_handler.setFormatter(file_formatter)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_formatter = logging.Formatter("%(levelname)s: %(message)s")
    console_handler.setFormatter(console_formatter)
    
    root.setLevel(level)
    root.addHandler(file_handler)
    root.addHandler(console_handler)


# =============================================================================
# Ponto de Entrada
# =============================================================================
async def main_async(args):
    """Função main assíncrona."""
    configurar_logging(args.verbose)
    escrever_pid()

    logging.info("=" * 60)
    logging.info("TermuxNetShield v2.0 - Pi-hole Style")
    logging.info("=" * 60)

    # Iniciar servidor DNS em thread separada
    dns_server = DNSServer(host=args.dns_host, port=args.dns_port, cname_uncloak=args.cname_uncloak)
    dns_thread = threading.Thread(target=dns_server.iniciar, daemon=True)
    dns_thread.start()

    # Aguardar servidor DNS iniciar
    await asyncio.sleep(1)

    # Iniciar interface web
    web_interface = WebInterface(dns_server, host=args.web_host, port=args.web_port)
    runner = await web_interface.start()

    try:
        # Manter rodando
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        logging.info("Interrompido pelo usuário.")
    finally:
        dns_server._parar()
        await runner.cleanup()
        remover_pid()
        logging.info("Servidor encerrado.")


def main():
    parser = argparse.ArgumentParser(
        description="TermuxNetShield — Pi-hole Style DNS Blocker"
    )
    parser.add_argument(
        "--dns-port", type=int, default=PORTA_DNS,
        help=f"Porta DNS (padrão: {PORTA_DNS})"
    )
    parser.add_argument(
        "--dns-host", type=str, default="127.0.0.1",
        help="Host DNS (padrão: 127.0.0.1)"
    )
    parser.add_argument(
        "--web-port", type=int, default=PORTA_WEB,
        help=f"Porta Web (padrão: {PORTA_WEB})"
    )
    parser.add_argument(
        "--web-host", type=str, default="0.0.0.0",
        help="Host Web (padrão: 0.0.0.0)"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Modo verbose"
    )
    parser.add_argument(
        "--no-cname-uncloak", dest="cname_uncloak", action="store_false",
        help="Desativar CNAME uncloaking"
    )

    args = parser.parse_args()

    try:
        asyncio.run(main_async(args))
    except Exception as e:
        logging.error("Erro fatal: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
