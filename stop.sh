#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# TermuxNetShield — stop.sh
# =============================================================================
# Para o servidor DNS bloqueador de anúncios de forma segura.
# Uso: bash stop.sh
# =============================================================================

set -e

# ─── Caminhos ────────────────────────────────────────────────────────────────
PROJETO="$HOME/TermuxNetShield"
LOGS_DIR="$PROJETO/logs"
PID_FILE="$LOGS_DIR/dns_server.pid"
LOG_FILE="$LOGS_DIR/dns_server.log"

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
echo -e "${AZUL}║    TermuxNetShield — Parando Serviço     ║${NC}"
echo -e "${AZUL}╚══════════════════════════════════════════╝${NC}"
echo ""

# ─── 1. Coletar estatísticas antes de parar ────────────────────────────────
BLOQUEADOS=0
LIBERADOS=0
TOTAL=0

if [ -f "$LOG_FILE" ]; then
    BLOQUEADOS=$(grep -c "🛡️ BLOQUEADO" "$LOG_FILE" 2>/dev/null || echo 0)
    LIBERADOS=$(grep -c "LIBERADO" "$LOG_FILE" 2>/dev/null || echo 0)
    TOTAL=$((BLOQUEADOS + LIBERADOS))
fi

# ─── 2. Verificar PID file ──────────────────────────────────────────────────
PID_ENCONTRADO=""
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        PID_ENCONTRADO="$PID"
        info "Parando servidor DNS (PID: $PID)..."
        kill "$PID" 2>/dev/null || true
    else
        rm -f "$PID_FILE"
    fi
fi

# ─── 3. Fallback: procurar pelo nome do processo ────────────────────────────
if [ -z "$PID_ENCONTRADO" ]; then
    PID=$(pgrep -f "python.*dns_server\.py" 2>/dev/null || true)
    if [ -n "$PID" ]; then
        PID_ENCONTRADO="$PID"
        info "Encontrado processo dns_server.py (PID: $PID). Parando..."
        kill "$PID" 2>/dev/null || true
    fi
fi

# ─── 4. Aguardar o processo terminar ────────────────────────────────────────
if [ -n "$PID_ENCONTRADO" ]; then
    for i in {1..5}; do
        if ! kill -0 "$PID_ENCONTRADO" 2>/dev/null; then
            break
        fi
        sleep 1
    done

    # Forçar se necessário
    if kill -0 "$PID_ENCONTRADO" 2>/dev/null; then
        aviso "Processo não respondeu. Forçando parada (SIGKILL)..."
        kill -9 "$PID_ENCONTRADO" 2>/dev/null || true
        sleep 1
    fi
fi

# ─── 5. Limpeza ─────────────────────────────────────────────────────────────
rm -f "$PID_FILE"

if [ -n "$PID_ENCONTRADO" ]; then
    sucesso "Servidor DNS parado (PID: $PID_ENCONTRADO)"
else
    aviso "Nenhum servidor DNS em execução."
fi

echo ""
echo -e "${AZUL}Estatísticas da sessão:${NC}"
echo "  Total consultas:    $TOTAL"
echo "  Bloqueados:         $BLOQUEADOS"
echo "  Liberados:          $LIBERADOS"

if [ "$TOTAL" -gt 0 ]; then
    TAXA=$((BLOQUEADOS * 100 / TOTAL))
    echo "  Taxa de bloqueio:  ${TAXA}%"
fi

echo ""
echo -e "${VERDE}Para analisar os logs em detalhes:${NC}"
echo "  python scripts/analyzer.py"
echo ""
