#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# TermuxNetShield — install.sh
# =============================================================================
# Script de instalação/configuração do projeto.
# Executar UMA VEZ antes de usar: bash install.sh
# =============================================================================

set -e  # Para o script se qualquer comando falhar

# ─── Caminhos ────────────────────────────────────────────────────────────────
PROJETO="$HOME/TermuxNetShield"

# ─── Cores para output ───────────────────────────────────────────────────────
VERDE='\033[0;32m'
AZUL='\033[0;34m'
AMARELO='\033[1;33m'
VERMELHO='\033[0;31m'
NC='\033[0m' # No Color

# ─── Utilitários de mensagem ────────────────────────────────────────────────
info()    { echo -e "${AZUL}[INFO]${NC} $1"; }
sucesso() { echo -e "${VERDE}[OK]${NC} $1"; }
aviso()   { echo -e "${AMARELO}[AVISO]${NC} $1"; }
erro()    { echo -e "${VERMELHO}[ERRO]${NC} $1"; }

echo ""
echo -e "${AZUL}╔══════════════════════════════════════════╗${NC}"
echo -e "${AZUL}║     TermuxNetShield — Instalação         ║${NC}"
echo -e "${AZUL}╚══════════════════════════════════════════╝${NC}"
echo ""

# ─── 1. Verificar se está no Termux ────────────────────────────────────────
if [ ! -d /data/data/com.termux ]; then
    aviso "Este script foi feito para o Termux no Android."
    aviso "Pode funcionar em outros Linux, mas sem garantia."
fi

# ─── 2. Atualizar pacotes do Termux ────────────────────────────────────────
info "Atualizando lista de pacotes..."
pkg update -y && sucesso "Pacotes atualizados"

# ─── 3. Instalar dependências ──────────────────────────────────────────────
info "Instalando dependências..."

# Python é essencial (nosso servidor DNS é em Python puro)
# curl para baixar blocklists, demais são utilitários
pkg install -y \
    python             \
    curl               \
    git                \
    jq                 \
    ncurses-utils      

sucesso "Pacotes do sistema instalados"

# ─── 4. Instalar dnslib (biblioteca DNS para Python) ───────────────────────
info "Instalando dnslib (biblioteca DNS para Python)..."
pip install dnslib 2>&1 | tail -3
sucesso "dnslib instalado"

# ─── 5. Verificar Python e dnslib ─────────────────────────────────────────
info "Verificando instalação..."
python --version || erro "Python não encontrado!"

if python -c "import dnslib" 2>/dev/null; then
    sucesso "dnslib funcionando"
else
    erro "Falha ao importar dnslib"
    exit 1
fi

# ─── 6. Criar diretórios do projeto ────────────────────────────────────────
info "Criando estrutura de diretórios..."
mkdir -p "$PROJETO"/{logs,blocklists,relatorios}
sucesso "Diretórios criados"

# ─── 7. Dar permissão de execução nos scripts ──────────────────────────────
info "Dando permissão de execução..."
chmod +x "$PROJETO"/*.sh "$PROJETO"/scripts/*.py
sucesso "Permissões aplicadas"

# ─── 8. Baixar blocklist inicial ───────────────────────────────────────────
info "Baixando blocklist inicial (~745k domínios)..."
bash "$PROJETO/update-blocklist.sh"
sucesso "Blocklist inicial baixada"

# ─── 9. Criar alias no bashrc (opcional) ───────────────────────────────────
BASHRC=~/.bashrc
ALIAS="alias shield='cd $PROJETO && ls -la'"
if grep -q "alias shield=" "$BASHRC" 2>/dev/null; then
    aviso "Alias 'shield' já existe no .bashrc"
else
    echo "" >> "$BASHRC"
    echo "# TermuxNetShield — atalho rápido" >> "$BASHRC"
    echo "$ALIAS" >> "$BASHRC"
    sucesso "Alias 'shield' adicionado ao .bashrc"
    info  "Recarregue com: source ~/.bashrc"
fi

# ─── 10. Mensagem final ────────────────────────────────────────────────────
echo ""
echo -e "${VERDE}╔══════════════════════════════════════════╗${NC}"
echo -e "${VERDE}║  Instalação concluída com sucesso! 🛡️   ║${NC}"
echo -e "${VERDE}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "${AZUL}Próximos passos:${NC}"
echo "  1. Iniciar bloqueio:    bash start.sh"
echo "  2. Logs ao vivo:        tail -f ~/TermuxNetShield/logs/dns_server.log"
echo "  3. Analisar tráfego:    python scripts/analyzer.py"
echo "  4. Atualizar listas:    bash update-blocklist.sh"
echo "  5. Recarregar blocklist na hora:  pkill -HUP -f dns_server"
echo "  6. Parar bloqueio:      bash stop.sh"
echo ""
echo -e "${AMARELO}DNS local rodando em:  127.0.0.1:5353${NC}"
echo ""
