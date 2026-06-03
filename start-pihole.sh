#!/bin/bash
# =============================================================================
# TermuxNetShield — Pi-hole Style — Start Script
# =============================================================================
# Inicia o servidor DNS com interface web estilo Pi-hole
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOGS_DIR="$PROJECT_DIR/logs"
PID_FILE="$LOGS_DIR/pihole_server.pid"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     TermuxNetShield v2.0 - Pi-hole Style              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Verificar dependências
check_dependencies() {
    echo -e "${YELLOW}Verificando dependências...${NC}"
    
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}ERRO: Python3 não encontrado${NC}"
        exit 1
    fi
    
    # Verificar bibliotecas Python
    python3 -c "import dnslib" 2>/dev/null || {
        echo -e "${YELLOW}Instalando dnslib...${NC}"
        pip install dnslib
    }
    
    python3 -c "import aiohttp" 2>/dev/null || {
        echo -e "${YELLOW}Instalando aiohttp...${NC}"
        pip install aiohttp
    }
    
    echo -e "${GREEN}✓ Dependências OK${NC}"
}

# Criar diretórios necessários
setup_directories() {
    echo -e "${YELLOW}Configurando diretórios...${NC}"
    mkdir -p "$LOGS_DIR"
    mkdir -p "$PROJECT_DIR/config"
    mkdir -p "$PROJECT_DIR/blocklists"
    
    # Criar arquivos de configuração se não existirem
    [ ! -f "$PROJECT_DIR/config/whitelist.txt" ] && touch "$PROJECT_DIR/config/whitelist.txt"
    [ ! -f "$PROJECT_DIR/config/blacklist.txt" ] && echo "# Blacklist personalizada" > "$PROJECT_DIR/config/blacklist.txt"
    
    echo -e "${GREEN}✓ Diretórios configurados${NC}"
}

# Verificar se já está rodando
check_running() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            echo -e "${YELLOW}Servidor já está rodando (PID: $PID)${NC}"
            echo -e "${YELLOW}Use './stop.sh' para parar antes de reiniciar${NC}"
            return 0
        else
            echo -e "${YELLOW}Removendo PID file antigo...${NC}"
            rm -f "$PID_FILE"
        fi
    fi
    return 1
}

# Iniciar servidor
start_server() {
    local DNS_PORT=${1:-5353}
    local WEB_PORT=${2:-8080}
    
    echo -e "${YELLOW}Iniciando servidor...${NC}"
    echo -e "  ${BLUE}DNS Port:${NC} $DNS_PORT"
    echo -e "  ${BLUE}Web Port:${NC} $WEB_PORT"
    echo ""
    
    cd "$PROJECT_DIR"
    
    # Iniciar em background
    nohup python3 "$SCRIPT_DIR/pihole_server.py" \
        --dns-port "$DNS_PORT" \
        --web-port "$WEB_PORT" \
        > "$LOGS_DIR/pihole_stdout.log" 2>&1 &
    
    PID=$!
    echo $PID > "$PID_FILE"
    
    # Aguardar inicialização
    sleep 2
    
    if ps -p $PID > /dev/null 2>&1; then
        echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  ✓ Servidor iniciado com sucesso!                      ║${NC}"
        echo -e "${GREEN}╠════════════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║  PID: $PID                                              ${NC}"
        echo -e "${GREEN}║  DNS:   127.0.0.1:$DNS_PORT                             ${NC}"
        echo -e "${GREEN}║  Web:   http://127.0.0.1:$WEB_PORT                      ${NC}"
        echo -e "${GREEN}║  Logs:  $LOGS_DIR                                       ${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${YELLOW}Para configurar seu dispositivo:${NC}"
        echo -e "  1. Aponte seu DNS para: 127.0.0.1:$DNS_PORT"
        echo -e "  2. Acesse o dashboard: http://127.0.0.1:$WEB_PORT"
        echo -e "  3. Use Ctrl+C ou ./stop.sh para parar"
        echo ""
        return 0
    else
        echo -e "${RED}╔════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  ✗ ERRO: Falha ao iniciar servidor                     ║${NC}"
        echo -e "${RED}╚════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${YELLOW}Verifique os logs:${NC}"
        echo -e "  $LOGS_DIR/pihole_stdout.log"
        echo -e "  $LOGS_DIR/dns_server.log"
        return 1
    fi
}

# Main
main() {
    check_dependencies
    setup_directories
    
    if check_running; then
        exit 0
    fi
    
    # Parse arguments
    DNS_PORT=5353
    WEB_PORT=8080
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dns-port)
                DNS_PORT="$2"
                shift 2
                ;;
            --web-port)
                WEB_PORT="$2"
                shift 2
                ;;
            -h|--help)
                echo "Uso: $0 [OPÇÕES]"
                echo ""
                echo "Opções:"
                echo "  --dns-port PORTA    Porta do servidor DNS (padrão: 5353)"
                echo "  --web-port PORTA    Porta da interface web (padrão: 8080)"
                echo "  -h, --help          Mostrar esta ajuda"
                exit 0
                ;;
            *)
                echo -e "${RED}Opção desconhecida: $1${NC}"
                exit 1
                ;;
        esac
    done
    
    start_server "$DNS_PORT" "$WEB_PORT"
}

main "$@"
