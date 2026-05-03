#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# TermuxNetShield — update-blocklist.sh
# =============================================================================
# Baixa blocklists de fontes Pi-hole e converte para dnsmasq.
# Fontes: OISD (principal), AdGuard, EasyList, StevenBlack, AnudeepND
# Total: ~2M+ domínios bloqueados (ads, trackers, malware, miners, phishing)
# Uso: bash update-blocklist.sh
# =============================================================================

set -e

# ─── Caminhos ────────────────────────────────────────────────────────────────
PROJETO="$HOME/TermuxNetShield"
BLOCKLIST_DIR="$PROJETO/blocklists"
BLOCKLIST_OUT="$BLOCKLIST_DIR/ads.conf"
TEMP_DIR="$BLOCKLIST_DIR/tmp"

# ─── Cores ───────────────────────────────────────────────────────────────────
VERDE='\033[0;32m'; AZUL='\033[0;34m'; AMARELO='\033[1;33m'
VERMELHO='\033[0;31m'; NC='\033[0m'
info()    { echo -e "${AZUL}[INFO]${NC} $1"; }
sucesso() { echo -e "${VERDE}[OK]${NC} $1"; }
aviso()   { echo -e "${AMARELO}[AVISO]${NC} $1"; }
erro()    { echo -e "${VERMELHO}[ERRO]${NC} $1"; }

echo ""
echo -e "${AZUL}╔══════════════════════════════════════════╗${NC}"
echo -e "${AZUL}║  TermuxNetShield — Atualizando Listas   ║${NC}"
echo -e "${AZUL}║  Modo Pi-hole: ~2M domínios bloqueados  ║${NC}"
echo -e "${AZUL}╚══════════════════════════════════════════╝${NC}"
echo ""

mkdir -p "$TEMP_DIR"

# =============================================================================
# FONTES DE BLOCKLIST (estilo Pi-hole)
# =============================================================================
# Cada entrada: [nome]="url|formato"
# formato = "hosts" (0.0.0.0 dominio), "dominios" (dominio por linha), "adguard" (regras AdGuard)
# =============================================================================

declare -A FONTES

# ── Principal: OISD Full (a mais recomendada pelo Pi-hole) ──────────────────
# ~1.4M domínios. Bloqueia ads, trackers, malware, phishing.
# Qualidade excelente, baixíssimos falsos positivos.
FONTES["OISD_Full"]="https://big.oisd.nl/|adblock"

# ── AdGuard DNS Filter ───────────────────────────────────────────────────────
# ~100k domínios. Mantida pela equipe AdGuard. Complementa OISD.
FONTES["AdGuard_DNS"]="https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt|adguard"

# ── StevenBlack Unified (já tinha, mas essencial) ──────────────────────────
# ~130k domínios. Unifica várias listas classicas.
FONTES["StevenBlack"]="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts|hosts"

# ── AnudeepND Adservers ─────────────────────────────────────────────────────
# ~40k domínios. Focada em servidores de anúncio indianos/asiáticos.
FONTES["AnudeepND_Ads"]="https://raw.githubusercontent.com/AnudeepND/blacklist/master/adservers.txt|dominios"

# ── SomeoneWhoCares ─────────────────────────────────────────────────────────
# ~15k domínios. Lista curada manualmente, boa para pegar rastreadores niche.
FONTES["SomeoneWhoCares"]="https://someonewhocares.org/hosts/zero/hosts|hosts"

# ── 1Hosts (Lite) ──────────────────────────────────────────────────────────
# ~65k domínios. Foco em privacidade, bloqueio de telemetria.
FONTES["1Hosts_Lite"]="https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt|hosts"

# =============================================================================

# ─── Baixar cada fonte ──────────────────────────────────────────────────────
info "Baixando blocklists de $(echo ${#FONTES[@]}) fontes..."
echo ""

TOTAL_BAIXADO=0
for NOME in "${!FONTES[@]}"; do
    IFS='|' read -r URL FORMATO <<< "${FONTES[$NOME]}"
    ARQUIVO_TEMP="$TEMP_DIR/${NOME}.txt"

    echo -ne "  [ ] $NOME...\r"

    if curl -sSL --connect-timeout 15 --max-time 60 "$URL" -o "$ARQUIVO_TEMP" 2>/dev/null; then
        LINHAS=$(wc -l < "$ARQUIVO_TEMP")
        TOTAL_BAIXADO=$((TOTAL_BAIXADO + LINHAS))
        echo -e "  ${VERDE}[OK]${NC} $NOME ($LINHAS linhas)"
    else
        echo -e "  ${AMARELO}[FALHA]${NC} $NOME (pulando)"
        rm -f "$ARQUIVO_TEMP"
    fi
done

echo ""
info "Total bruto baixado: $TOTAL_BAIXADO linhas"

# ─── Mesclar e converter ───────────────────────────────────────────────────
info "Mesclando e convertendo para formato dnsmasq..."
echo "  (extraindo domínios, removendo duplicatas...)"

# Processo: pega TODOS os arquivos, extrai domínios, dedup, converte
# O resultado final tem ~2M domínios únicos
{
    # Processa arquivos em formato "hosts" (0.0.0.0 dominio)
    for f in "$TEMP_DIR"/*.txt; do
        [ -f "$f" ] || continue
        nome=$(basename "$f" .txt)

        case "$nome" in
            OISD_Full)
                # Formato Adblock Plus: ||dominio^
                # Exceções começam com @@|| (whitelist) — devem ser ignoradas
                grep -v '^@@' "$f" \
                    | grep -E '^\|\|' \
                    | sed 's/^\|\|//; s/\^$//; s/\^.*$//' \
                    | grep -v -E '^\*|\*$|[/: ]' \
                    || true
                ;;
            1Hosts_Lite|StevenBlack|SomeoneWhoCares)
                # Formato hosts: extrair domínios após 0.0.0.0
                grep -E '^0\.0\.0\.0\s' "$f" \
                    | awk '{print $2}' \
                    | grep -v -E '^(#|localhost|localhost\.localdomain|broadcasthost|local|ip6-|0\.0\.0\.0)' \
                    || true
                ;;
            AdGuard_DNS)
                # Formato AdGuard: "||dominio^" ou "domain.com"
                # Exceções começam com @@|| — ignorar
                grep -v '^@@' "$f" \
                    | grep -E '^\|\|[^\^]+\^' \
                    | sed 's/^||//; s/\^$//' \
                    || true
                ;;
            AnudeepND_Ads)
                # Domínios puros (um por linha)
                grep -v -E '^(#|$)' "$f" \
                    | tr -d '\r' \
                    || true
                ;;
        esac
    done
} | LC_ALL=C sort -u > "$TEMP_DIR/dominios_unicos.txt"

TOTAL_UNICOS=$(wc -l < "$TEMP_DIR/dominios_unicos.txt")
sucesso "$TOTAL_UNICOS domínios únicos extraídos"

# ─── Converter para formato dnsmasq ───────────────────────────────────────
info "Convertendo para dnsmasq (address=/dominio/0.0.0.0)..."

# Cabeçalho
{
    echo "# ==============================================================="
    echo "# TermuxNetShield — Blocklist Pi-hole Style"
    echo "# Gerado em: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# Domínios bloqueados: $TOTAL_UNICOS"
    echo "# Fontes:"
    for NOME in "${!FONTES[@]}"; do
        IFS='|' read -r URL FORMATO <<< "${FONTES[$NOME]}"
        echo "#   - $NOME: $URL"
    done
    echo "# ==============================================================="
    echo ""
} > "$BLOCKLIST_OUT"

# Converte para address=/dominio/0.0.0.0 (em lote, eficiente)
sed 's/^/address=\//; s/$/\/0.0.0.0/' "$TEMP_DIR/dominios_unicos.txt" >> "$BLOCKLIST_OUT"

TOTAL_FINAL=$(grep -c "^address=" "$BLOCKLIST_OUT" || echo 0)
sucesso "Blocklist final: $TOTAL_FINAL regras de bloqueio"

# ─── Métricas ──────────────────────────────────────────────────────────────
echo ""
echo -e "${AZUL}📊 MÉTRICAS${NC}"
echo "  Domínios únicos bloqueados:  $(printf "%'d" "$TOTAL_FINAL")"
echo "  Tamanho do arquivo:          $(du -h "$BLOCKLIST_OUT" | cut -f1)"
echo ""

# Recomendações baseadas no tamanho
if [ "$TOTAL_FINAL" -gt 1000000 ]; then
    echo -e "${VERDE}🔥 Cobertura excelente! Comparável ao Pi-hole.${NC}"
elif [ "$TOTAL_FINAL" -gt 500000 ]; then
    echo -e "${AMARELO}👍 Boa cobertura. Considere adicionar mais fontes em update-blocklist.sh.${NC}"
fi

# ─── Limpeza ────────────────────────────────────────────────────────────────
info "Limpando arquivos temporários..."
rm -rf "$TEMP_DIR"
sucesso "Limpeza concluída"

echo ""
echo -e "${AMARELO}Para aplicar: pkill -HUP -f dns_server${NC}"
echo "  (recarrega a blocklist sem reiniciar o servidor)"
echo ""
