#!/usr/bin/env python3
"""
TermuxNetShield — DNS-over-TLS Proxy 🛡️
=========================================
Proxy DoT que ouve na porta 853 (TLS) e encaminha consultas
para o netshild (127.0.0.1:5353).

Funciona com o Private DNS nativo do Android (sem root).
Gera automaticamente CA + certificado na primeira execução.
"""

import argparse
import asyncio
import logging
import os
import socket
import subprocess
import sys
import ssl
from datetime import datetime, timedelta

# ─── Caminhos ────────────────────────────────────────────────────────────────
HOME = os.path.expanduser("~")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJETO = os.path.dirname(SCRIPT_DIR)
CERTS_DIR = os.path.join(PROJETO, "config", "certs")
CA_KEY = os.path.join(CERTS_DIR, "ca-key.pem")
CA_CERT = os.path.join(CERTS_DIR, "ca-cert.pem")
SERVER_KEY = os.path.join(CERTS_DIR, "server-key.pem")
SERVER_CERT = os.path.join(CERTS_DIR, "server-cert.pem")
SERVER_P12 = os.path.join(CERTS_DIR, "server.p12")  # Para importar no Android
CA_DER = os.path.join(CERTS_DIR, "ca-cert.der")  # Formato DER para Android
LOG_PATH = os.path.join(PROJETO, "logs", "dot_proxy.log")

# ─── Configuração ────────────────────────────────────────────────────────────
DOT_PORT = 853
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 5353
BUFFER_SIZE = 4096


def _detectar_ip_rede():
    """Detecta o IP do dispositivo na rede WiFi (mesma lógica do shield.py)."""
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


def _gerar_certificados():
    """
    Gera uma CA auto-assinada + certificado do servidor.
    Usa o hostname nip.io (<IP>.nip.io) para compatibilidade com
    Android Private DNS.
    """
    os.makedirs(CERTS_DIR, exist_ok=True)

    ip = _detectar_ip_rede()
    if not ip:
        ip = "127.0.0.1"

    hostname_dns = f"{ip}.nip.io"

    print(f"  Gerando certificados para: {hostname_dns}")
    print(f"  IP do dispositivo: {ip}")
    print()

    # 1. Gerar chave da CA
    subprocess.run([
        "openssl", "genrsa", "-out", CA_KEY, "4096"
    ], check=True, capture_output=True)

    # 2. Gerar certificado da CA (válido por 10 anos)
    subprocess.run([
        "openssl", "req", "-x509", "-new", "-nodes",
        "-key", CA_KEY, "-sha256", "-days", "3650",
        "-out", CA_CERT,
        "-subj", "/CN=TermuxNetShield Root CA/O=LocalNetwork/C=BR"
    ], check=True, capture_output=True)

    # 3. Gerar chave do servidor
    subprocess.run([
        "openssl", "genrsa", "-out", SERVER_KEY, "2048"
    ], check=True, capture_output=True)

    # 4. Criar CSR para o servidor com SANs
    # O Android Private DNS verifica o nome do host contra o SAN do certificado
    sans = [
        f"DNS:{hostname_dns}",
        f"DNS:localhost",
        f"IP:{ip}",
        f"IP:127.0.0.1",
    ]

    # Criar config openssl para o CSR
    config_path = os.path.join(CERTS_DIR, "server.cnf")
    with open(config_path, "w") as f:
        f.write(f"""[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
CN = {hostname_dns}
O = TermuxNetShield
C = BR

[req_ext]
subjectAltName = @alt_names

[alt_names]
{chr(10).join(f"{'DNS.' + str(i+1) if s.startswith('DNS:') else 'IP.' + str(i+1)} = {s.split(':',1)[1]}" for i, s in enumerate(sans))}
""")

    subprocess.run([
        "openssl", "req", "-new",
        "-key", SERVER_KEY,
        "-out", os.path.join(CERTS_DIR, "server.csr"),
        "-config", config_path
    ], check=True, capture_output=True)

    # 5. Assinar CSR com a CA
    subprocess.run([
        "openssl", "x509", "-req",
        "-in", os.path.join(CERTS_DIR, "server.csr"),
        "-CA", CA_CERT,
        "-CAkey", CA_KEY,
        "-CAcreateserial",
        "-out", SERVER_CERT,
        "-days", "3650",
        "-sha256",
        "-extfile", config_path,
        "-extensions", "req_ext"
    ], check=True, capture_output=True)

    # 6. Converter CA para DER (formato que o Android entende para instalação)
    subprocess.run([
        "openssl", "x509", "-in", CA_CERT,
        "-outform", "DER", "-out", CA_DER
    ], check=True, capture_output=True)

    # 7. Gerar PKCS12 para importação no Android (opcional)
    subprocess.run([
        "openssl", "pkcs12", "-export",
        "-in", SERVER_CERT,
        "-inkey", SERVER_KEY,
        "-out", SERVER_P12,
        "-passout", "pass:"
    ], check=True, capture_output=True)

    # Limpeza
    for f in ["server.csr", "server.cnf"]:
        path = os.path.join(CERTS_DIR, f)
        if os.path.exists(path):
            os.remove(path)

    # Remover serial da CA
    for f in os.listdir(CERTS_DIR):
        if f.endswith(".srl"):
            os.remove(os.path.join(CERTS_DIR, f))

    print(f"  ✅ CA:     {CA_CERT}")
    print(f"  ✅ Cert:   {SERVER_CERT}")
    print(f"  ✅ Chave:  {SERVER_KEY}")
    print(f"  ✅ Android: {CA_DER}")
    print()

    return hostname_dns, ip


def _criar_contexto_ssl():
    """Cria um contexto SSL com o certificado do servidor."""
    if not os.path.exists(SERVER_CERT) or not os.path.exists(SERVER_KEY):
        print("  Gerando certificados pela primeira vez...")
        _gerar_certificados()

    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.load_cert_chain(SERVER_CERT, SERVER_KEY)
    contexto.check_hostname = False
    # Configurações de segurança razoáveis
    contexto.minimum_version = ssl.TLSVersion.TLSv1_2
    return contexto


class DotProtocol(asyncio.Protocol):
    """
    Manipula uma conexão DNS-over-TLS.
    Cada conexão TLS recebe consultas DNS e as encaminha para o upstream.
    """

    def __init__(self, upstream_host, upstream_port):
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.transport = None
        self._buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        peer = transport.get_extra_info("peername")
        logging.debug("Nova conexão TLS de %s", peer)

    def data_received(self, data):
        """
        Recebe dados TLS (consulta DNS com prefixo de 2 bytes do RFC 7858).
        Formato DoT: [2 bytes length][consulta DNS...]
        """
        self._buffer += data

        while len(self._buffer) >= 2:
            # Ler o comprimento (2 bytes, big-endian)
            comprimento = (self._buffer[0] << 8) | self._buffer[1]
            pacote_completo = comprimento + 2  # +2 pelos bytes de comprimento

            if len(self._buffer) < pacote_completo:
                break  # Aguardar mais dados

            # Extrair consulta DNS (pulando os 2 bytes de comprimento)
            consulta_dns = self._buffer[2:pacote_completo]
            self._buffer = self._buffer[pacote_completo:]

            # Encaminhar para upstream (netshild)
            asyncio.create_task(self._encaminhar(consulta_dns))

    async def _encaminhar(self, consulta_dns):
        """Encaminha consulta DNS para o netshild e retorna resposta."""
        try:
            loop = asyncio.get_event_loop()
            resposta = await loop.run_in_executor(
                None, self._consultar_upstream, consulta_dns
            )
            if resposta and self.transport:
                # Adicionar prefixo de 2 bytes (comprimento)
                comprimento = len(resposta).to_bytes(2, "big")
                self.transport.write(comprimento + resposta)
        except Exception as e:
            logging.error("Erro ao encaminhar consulta: %s", e)

    def _consultar_upstream(self, consulta_dns):
        """Consulta o upstream DNS via UDP (bloqueante, roda em thread)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            sock.sendto(consulta_dns, (self.upstream_host, self.upstream_port))
            resposta, _ = sock.recvfrom(4096)
            sock.close()
            return resposta
        except socket.timeout:
            logging.warning("Timeout no upstream %s:%s", self.upstream_host, self.upstream_port)
            return None
        except Exception as e:
            logging.error("Erro no upstream: %s", e)
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def connection_lost(self, exc):
        logging.debug("Conexão TLS encerrada")
        self.transport = None


def configurar_logging():
    """Configura logging para arquivo e console."""
    level = logging.INFO

    # Handler para arquivo
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
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


async def main():
    parser = argparse.ArgumentParser(
        description="TermuxNetShield — DNS-over-TLS Proxy"
    )
    parser.add_argument("--port", type=int, default=DOT_PORT,
                        help=f"Porta DoT (padrão: {DOT_PORT})")
    parser.add_argument("--upstream-host", default=UPSTREAM_HOST,
                        help=f"Upstream DNS (padrão: {UPSTREAM_HOST})")
    parser.add_argument("--upstream-port", type=int, default=UPSTREAM_PORT,
                        help=f"Porta upstream (padrão: {UPSTREAM_PORT})")
    parser.add_argument("--gen-certs", action="store_true",
                        help="Apenas gerar certificados e sair")
    parser.add_argument("--show-ca", action="store_true",
                        help="Mostrar instruções de instalação da CA")
    args = parser.parse_args()

    configurar_logging()

    # Gerar certificados se necessário
    if not os.path.exists(SERVER_CERT):
        hostname_dns, ip = _gerar_certificados()
    else:
        ip = _detectar_ip_rede() or "127.0.0.1"
        hostname_dns = f"{ip}.nip.io"

    # Só gerar certificados
    if args.gen_certs:
        hostname_dns, ip = _gerar_certificados()
        return

    # Mostrar instruções da CA
    if args.show_ca:
        ip = _detectar_ip_rede() or "127.0.0.1"
        hostname_dns = f"{ip}.nip.io"
        _mostrar_instrucoes_ca(hostname_dns, ip)
        return

    # Iniciar servidor DoT
    contexto = _criar_contexto_ssl()

    loop = asyncio.get_event_loop()

    # Factory que passa upstream config para cada protocolo
    def protocol_factory():
        return DotProtocol(args.upstream_host, args.upstream_port)

    try:
        server = await loop.create_server(
            protocol_factory,
            host="0.0.0.0",
            port=args.port,
            ssl=contexto
        )
    except PermissionError:
        logging.error("═" * 50)
        logging.error("PERMISSÃO NEGADA para porta %d!", args.port)
        logging.error("")
        logging.error("Portas < 1024 exigem root no Android.")
        logging.error("O DNS-over-TLS do Android (Private DNS) usa apenas")
        logging.error("a porta 853, que não pode ser usada sem root.")
        logging.error("")
        logging.error("Alternativas para usar o netshild no Android:")
        logging.error("  1. shield network  — Bloqueia na rede WiFi (outros dispositivos)")
        logging.error("  2. PersonalDNSfilter (F-Droid) — VPN local, sem root")
        logging.error("  3. Root + iptables — redirect 53→5353")
        logging.error("═" * 50)
        sys.exit(1)

    logging.info("═" * 50)
    logging.info("DNS-over-TLS Proxy iniciado 🛡️")
    logging.info("═" * 50)
    logging.info("Ouvindo em:      0.0.0.0:%d (TLS)", args.port)
    logging.info("Upstream DNS:    %s:%d", args.upstream_host, args.upstream_port)
    logging.info("Hostname DoT:    %s", hostname_dns)
    logging.info("IP do servidor:  %s", ip)
    logging.info("CA Cert:         %s", CA_CERT)
    logging.info("Logs:            %s", LOG_PATH)
    logging.info("═" * 50)

    print()
    print("  🛡️  DNS-over-TLS Proxy rodando!")
    print(f"  📡 Hostname: {hostname_dns}")
    print(f"  🔌 Porta:    {args.port}")
    print()
    print("  Configure o Private DNS do Android:")
    print(f"    Ajustes → Rede → DNS Privado → {hostname_dns}")
    print()

    async with server:
        await server.serve_forever()


def _mostrar_instrucoes_ca(hostname_dns, ip):
    """Mostra instruções para instalar a CA no Android."""
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║    Instalação da CA no Android                      ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()
    print(f"  Hostname DoT: {hostname_dns}")
    print(f"  Arquivo CA:   {CA_DER}")
    print()
    print("  Passo 1 — Copie o arquivo CA para o celular:")
    print(f"    cp {CA_DER} ~/storage/downloads/")
    print()
    print("  Passo 2 — Abra as configurações e instale:")
    print("     Ajustes → Segurança → Credenciais → Instalar certificado")
    print("     Selecione o arquivo 'ca-cert.der' baixado")
    print("     (é um certificado de CA — confirme a instalação)")
    print()
    print("  Passo 3 — Configure o Private DNS:")
    print(f"     Ajustes → Rede → DNS Privado → {hostname_dns}")
    print()
    print("  Pronto! Todo DNS do Android passará pelo netshild. 🛡️")
    print()


if __name__ == "__main__":
    asyncio.run(main())
