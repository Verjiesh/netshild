#!/usr/bin/env bash
# =============================================================================
# TermuxNetShield — Auto-start (Termux:Boot)
# =============================================================================
# Inicia o netshild automaticamente ao ligar o celular.
#
# Pré-requisito: Instale Termux:Boot (F-Droid) e execute:
#   shield boot-enable
# =============================================================================

# Detecta o diretório do projeto
SCRIPT="$(readlink -f "$0")"
PROJETO="$(dirname "$SCRIPT")"
if [[ "$PROJETO" == *".termux/boot"* ]]; then
    PROJETO="$HOME/netshild"
fi

# Aguardar rede ficar disponível e sistema carregar
sleep 20

# Iniciar servidor DNS bloqueador
cd "$PROJETO" || exit 1
python3 shield.py start >> "$PROJETO/logs/boot.log" 2>&1

echo "[$(date '+%Y-%m-%d %H:%M:%S')] netshild iniciado" >> "$PROJETO/logs/boot.log"
