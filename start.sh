#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# TermuxNetShield — start.sh
# =============================================================================
# Inicia o servidor DNS bloqueador de anúncios (Python + dnslib).
# Uso: bash start.sh
# =============================================================================

set -e

# ─── Caminhos ────────────────────────────────────────────────────────────────
PROJETO="$HOME/TermuxNetShield"
DNS_SERVER="$PROJETO/scripts/dns_server.py"
LOGS_DIR="$PROJETO/logs"
LOG_FILE="$LOGS_DIR/dns_server.log"
PID_FILE="$LOGS_DIR/dns_server.pid"
BLOCKLIST="$PROJETO/blocklists/ads.conf"

# ─── Cores ───────────────────────────────────────────────────────────────────
VERDE='\033[0;32m'
AZUL='\033[0;34m'
AMARELO='\033[1;33m'
VERMELHO='\033[0;31m'
NC='\033[0m'

info()    { echo -e "${AZUL}[INFO]${NC} $1"; }
sucesso() { echo -e "${VERDE}[OK]${NC} $1"; }
aviso()   { echo -e "${AMARELO}[AVISO]${NC} $1"; }
erro()    { echo -e "${VERMELHO}[ERRO]${NC} $1"; }

echo ""
echo -e "${AZUL}╔══════════════════════════════════════════╗${NC}"
echo -e "${AZUL}║   TermuxNetShield — Iniciando Serviço    ║${NC}"
echo -e "${AZUL}╚══════════════════════════════════════════╝${NC}"
echo ""

# ─── 1. Verificar Python e dnslib ──────────────────────────────────────────
if ! command -v python &>/dev/null; then
    erro "Python não encontrado! Execute 'bash install.sh' primeiro."
    exit 1
fi

if ! python -c "import dnslib" 2>/dev/null; then
    erro "Biblioteca 'dnslib' não instalada!"
    info "Instale com: pip install dnslib"
    exit 1
fi

# ─── 2. Verificar se já está rodando ────────────────────────────────────────
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        aviso "Servidor DNS já está rodando (PID: $PID)"
        aviso "Reinicie com: bash stop.sh && bash start.sh"
        exit 0
    else
        info "Removendo PID obsoleto..."
        rm -f "$PID_FILE"
    fi
fi

# ─── 3. Verificar blocklist ─────────────────────────────────────────────────
if [ ! -f "$BLOCKLIST" ]; then
    aviso "Blocklist não encontrada! Baixando agora..."
    bash "$PROJETO/update-blocklist.sh"
fi

# ─── 4. Criar diretório de logs ─────────────────────────────────────────────
mkdir -p "$LOGS_DIR"

# ─── 5. Iniciar servidor DNS em background ─────────────────────────────────
info "Iniciando servidor DNS na porta 5353..."
python "$DNS_SERVER" --port 5353 --host 127.0.0.1 &

# Salvar o PID do processo em background
PID=$!
echo "$PID" > "$PID_FILE"

# ─── 6. Aguardar inicialização ─────────────────────────────────────────────
sleep 2

# ─── 7. Verificar se iniciou corretamente ──────────────────────────────────
if kill -0 "$PID" 2>/dev/null; then
    sucesso "Servidor DNS rodando (PID: $PID)"

    # Mostrar estatísticas da blocklist
    if [ -f "$BLOCKLIST" ]; then
        TOTAL_DOMINIOS=$(grep -c "^address=" "$BLOCKLIST" 2>/dev/null || echo 0)
    else
        TOTAL_DOMINIOS=0
    fi

    echo ""
    echo -e "${AZUL}Informações:${NC}"
    echo "  DNS local:      127.0.0.1:5353"
    echo "  Logs:           $LOG_FILE"
    echo "  Blocklist:      $TOTAL_DOMINIOS domínios bloqueados"
    echo "  PID:            $PID"
    echo ""
    echo -e "${AMARELO}Recarregar blocklist sem reiniciar:${NC}"
    echo "  pkill -HUP -f dns_server"
    echo ""
    echo -e "${VERDE}Logs ao vivo:${NC}"
    echo "  tail -f $LOG_FILE"
    echo ""
    echo -e "${AMARELO}Configurar no Android:${NC}"
    echo "  Para bloquear em todo o sistema, use um app como"
    echo "  PersonalDNSfilter ou NetGuard com upstream em:"
    echo "  DNS: 127.0.0.1 : 5353"
    echo ""
else
    erro "Falha ao iniciar servidor DNS."
    erro "Verifique os logs: $LOG_FILE"
    tail -5 "$LOG_FILE" 2>/dev/null || true
    rm -f "$PID_FILE"
    exit 1
fi
