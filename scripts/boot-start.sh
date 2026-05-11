#!/usr/bin/env bash
# =============================================================================
# TermuxNetShield — Auto-start (Termux:Boot)
# =============================================================================
# Coloque este script em ~/.termux/boot/ para iniciar o netshild
# automaticamente ao ligar o celular.
#
# Pré-requisito: Instale Termux:Boot (F-Droid) e execute:
#   shield boot-enable
# =============================================================================

# Detecta o diretório do projeto (funciona mesmo com symlink do Termux:Boot)
SCRIPT="$(readlink -f "$0")"
PROJETO="$(dirname "$SCRIPT")"

# Se estiver em ~/.termux/boot/, sobe até o ~/netshild
if [[ "$PROJETO" == *".termux/boot"* ]]; then
    PROJETO="$HOME/netshild"
fi

# Aguardar rede ficar disponível
sleep 15

# Iniciar servidor DNS
cd "$PROJETO" || exit 1
exec python3 shield.py start --host 0.0.0.0 >> "$PROJETO/logs/boot.log" 2>&1
