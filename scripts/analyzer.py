#!/data/data/com.termux/files/usr/bin/env python3
# =============================================================================
# TermuxNetShield — analyzer.py
# =============================================================================
# Analisa os logs de DNS gerados pelo dnsmasq e exibe estatísticas sobre
# consultas, bloqueios, domínios mais frequentes, etc.
# Uso: python scripts/analyzer.py [--relatorio]
# =============================================================================

import os
import re
import sys
from collections import Counter
from datetime import datetime

# ─── Configurações ───────────────────────────────────────────────────────────
HOME = os.path.expanduser("~")
LOG_FILE = os.path.join(HOME, "TermuxNetShield", "logs", "dns_server.log")
RELATORIO_DIR = os.path.join(HOME, "TermuxNetShield", "relatorios")
BLOCKLIST_FILE = os.path.join(HOME, "TermuxNetShield", "blocklists", "ads.conf")


# ─── Utilitários de terminal ────────────────────────────────────────────────
def cor(texto, codigo):
    """Aplica cor ANSI ao texto."""
    cores = {
        "verde": "32", "azul": "34", "amarelo": "33",
        "vermelho": "31", "ciano": "36", "roxo": "35",
    }
    return f"\033[{cores.get(codigo, '0')}m{texto}\033[0m"


def cabecalho(titulo):
    """Exibe um cabeçalho formatado."""
    print()
    print(cor("═" * 50, "azul"))
    print(cor(f"  {titulo}", "azul"))
    print(cor("═" * 50, "azul"))
    print()


def info(msg):
    print(cor("[INFO]", "azul"), msg)


def sucesso(msg):
    print(cor("[OK]", "verde"), msg)


def aviso(msg):
    print(cor("[AVISO]", "amarelo"), msg)


def erro(msg):
    print(cor("[ERRO]", "vermelho"), msg)


# ─── Parsing de logs ────────────────────────────────────────────────────────
def parse_logs(caminho_log):
    """
    Analisa o arquivo de log do dnsmasq e extrai informações estruturadas.

    Retorna um dicionário com:
    - total_consultas: número total de consultas DNS
    - dominios_consultados: Counter com domínios e frequência
    - dominios_bloqueados: Counter com domínios bloqueados (resolvidos para 0.0.0.0)
    - timestamps: lista de horários das consultas
    """
    dados = {
        "total_consultas": 0,
        "dominios_consultados": Counter(),
        "dominios_bloqueados": Counter(),
        "timestamps": [],
    }

    # Padrão: "query[AAAA] dominio.com" ou "query[A] dominio.com"
    padrao_consulta = re.compile(r"query\[(?:AAAA|A|MX|TXT|CNAME)\]\s+(\S+)")

    # Padrão de bloqueio: "domain.com is 0.0.0.0" ou "reply domain.com is 0.0.0.0"
    padrao_bloqueio = re.compile(r"is\s+(0\.0\.0\.0|::)")

    # Timestamp: log tem formato "Jan  1 12:34:56 dnsmasq[..."
    padrao_timestamp = re.compile(r"^(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})")

    if not os.path.exists(caminho_log):
        aviso(f"Arquivo de log não encontrado: {caminho_log}")
        return dados

    with open(caminho_log, "r", encoding="utf-8", errors="ignore") as f:
        for linha in f:
            linha = linha.strip()

            # Extrair timestamp
            match_ts = padrao_timestamp.search(linha)
            if match_ts:
                dados["timestamps"].append(match_ts.group(1))

            # Extrair consulta DNS
            match_q = padrao_consulta.search(linha)
            if match_q:
                dominio = match_q.group(1).lower()
                dados["dominios_consultados"][dominio] += 1
                dados["total_consultas"] += 1

                # Verificar se foi bloqueado (0.0.0.0)
                if padrao_bloqueio.search(linha):
                    dados["dominios_bloqueados"][dominio] += 1

    return dados


# ─── Bloqueadores mais frequentes (baseado na blocklist) ─────────────────────
def carregar_blocklist(caminho):
    """
    Carrega a blocklist e retorna estatísticas sobre ela.
    """
    if not os.path.exists(caminho):
        aviso(f"Blocklist não encontrada: {caminho}")
        return {"total": 0, "exemplos": []}

    dominios = []
    with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
        for linha in f:
            linha = linha.strip()
            # Formato: address=/dominio.com/0.0.0.0
            match = re.match(r"address=/([^/]+)/", linha)
            if match:
                dominios.append(match.group(1))

    # Amostra aleatória de 10 domínios para exibir
    exemplos = dominios[:10]

    return {
        "total": len(dominios),
        "exemplos": exemplos,
    }


# ─── Relatório principal ───────────────────────────────────────────────────
def gerar_relatorio(dados_log, blocklist, salvar_arquivo=False):
    """
    Gera e exibe o relatório completo de análise.
    """
    cabecalho("RELATÓRIO DE ANÁLISE DNS")

    # ── Informações gerais ──
    print(cor("📊 INFORMAÇÕES GERAIS", "ciano"))
    print(f"  Log analisado:      {LOG_FILE}")

    if dados_log["timestamps"]:
        print(f"  Primeira consulta:  {dados_log['timestamps'][0]}")
        print(f"  Última consulta:    {dados_log['timestamps'][-1]}")

    duracao = 0
    if len(dados_log["timestamps"]) >= 2:
        try:
            t1 = dados_log["timestamps"][0]
            t2 = dados_log["timestamps"][-1]
            fmt = "%b %d %H:%M:%S"
            # Usar ano atual para strptime
            ano_atual = datetime.now().year
            dt1 = datetime.strptime(f"{ano_atual} {t1}", f"%Y {fmt}")
            dt2 = datetime.strptime(f"{ano_atual} {t2}", f"%Y {fmt}")
            duracao = (dt2 - dt1).total_seconds()
            if duracao < -86400:
                # Virou mais de um dia (ex: segundos de logging entre meses diferentes)
                duracao += 86400 * 2
            elif duracao < 0:
                duracao += 86400  # virou o dia
            if duracao > 0:
                print(f"  Período analisado:  ~{duracao / 60:.0f} minutos")
        except ValueError:
            pass

    print()

    # ── Estatísticas de consultas ──
    print(cor("🔍 ESTATÍSTICAS DE CONSULTAS", "ciano"))
    total = dados_log["total_consultas"]
    bloqueados = sum(dados_log["dominios_bloqueados"].values())
    liberados = total - bloqueados

    print(f"  Total consultas:    {total}")
    print(f"  Domínios únicos:    {len(dados_log['dominios_consultados'])}")
    print(f"  Bloqueados 🛡️:     {cor(str(bloqueados), 'verde')}")
    print(f"  Liberados ✅:       {liberados}")

    if total > 0:
        taxa_bloqueio = (bloqueados / total) * 100
        qps = total / duracao if duracao > 0 else 0
        print(f"  Taxa de bloqueio:   {taxa_bloqueio:.1f}%")
        print(f"  Consultas/minuto:   {qps * 60:.1f}")
    print()

    # ── Top 10 domínios consultados ──
    print(cor("🏆 TOP 10 DOMÍNIOS MAIS CONSULTADOS", "ciano"))
    top_consultados = dados_log["dominios_consultados"].most_common(10)
    if top_consultados:
        for i, (dominio, qtd) in enumerate(top_consultados, 1):
            # Marcar se este domínio foi bloqueado
            eh_bloqueado = " 🛡️" if dominio in dados_log["dominios_bloqueados"] else ""
            print(f"  {i:2d}. {dominio:<40s} {qtd:>5d}x{eh_bloqueado}")
    else:
        print("  (Nenhuma consulta registrada)")
    print()

    # ── Top 10 bloqueios ──
    print(cor("🚫 TOP 10 DOMÍNIOS BLOQUEADOS", "ciano"))
    top_bloqueados = dados_log["dominios_bloqueados"].most_common(10)
    if top_bloqueados:
        for i, (dominio, qtd) in enumerate(top_bloqueados, 1):
            print(f"  {i:2d}. {dominio:<40s} {qtd:>5d}x 🛡️")
    else:
        print("  (Nenhum bloqueio registrado)")
    print()

    # ── Blocklist ──
    print(cor("📋 ESTATÍSTICAS DA BLOCKLIST", "ciano"))
    print(f"  Total domínios bloqueados: {blocklist['total']}")
    if blocklist["exemplos"]:
        print(cor("  Amostra de domínios:", "amarelo"))
        for dom in blocklist["exemplos"][:5]:
            print(f"    • {dom}")
    print()

    # ── Recomendações ──
    print(cor("💡 RECOMENDAÇÕES", "ciano"))
    if taxa_bloqueio < 5 and bloqueados > 0:
        print("  • Taxa de bloqueio baixa — considere adicionar mais fontes de")
        print("    blocklist no update-blocklist.sh")
    elif taxa_bloqueio > 50:
        print("  • Taxa de bloqueio muito alta! Verifique se sites legítimos")
        print("    estão sendo bloqueados incorretamente (falso positivo).")
    if total > 1000:
        print("  • Alto volume de consultas — o cache do servidor DNS está")
        print("    ajudando a reduzir tráfego para os upstreams.")

    # ── Salvar relatório ──
    if salvar_arquivo:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs(RELATORIO_DIR, exist_ok=True)
        caminho_rel = os.path.join(RELATORIO_DIR, f"relatorio_{timestamp}.txt")
        with open(caminho_rel, "w", encoding="utf-8") as f:
            # Salva dados consolidados em formato legível
            f.write(f"Relatório TermuxNetShield - {datetime.now()}\n")
            f.write(f"{'='*50}\n")
            f.write(f"Total consultas: {total}\n")
            f.write(f"Bloqueados: {bloqueados}\n")
            f.write(f"Taxa bloqueio: {taxa_bloqueio:.1f}%\n")
            f.write(f"\nTop 10 bloqueados:\n")
            for dom, qtd in top_bloqueados:
                f.write(f"  {dom} - {qtd}x\n")

        sucesso(f"Relatório salvo em: {caminho_rel}")

    return {
        "total_consultas": total,
        "bloqueados": bloqueados,
        "taxa_bloqueio": f"{taxa_bloqueio:.1f}%",
    }


# ─── Ponto de entrada ───────────────────────────────────────────────────────
def main():
    """Função principal — executa a análise."""
    # Verificar argumentos
    gerar_relatorio_file = "--relatorio" in sys.argv

    print()
    print(cor("╔══════════════════════════════════════════╗", "azul"))
    print(cor("║   TermuxNetShield — Analisador de Logs   ║", "azul"))
    print(cor("╚══════════════════════════════════════════╝", "azul"))

    # Carregar dados
    info("Analisando logs...")
    dados_log = parse_logs(LOG_FILE)

    info("Carregando blocklist...")
    blocklist = carregar_blocklist(BLOCKLIST_FILE)

    # Gerar relatório
    if dados_log["total_consultas"] == 0:
        aviso("Nenhuma consulta DNS encontrada no log.")
        aviso("Certifique-se de que o servidor DNS está rodando (bash start.sh)")
        aviso("e que há tráfego de rede sendo roteado por ele.")
        return

    resultado = gerar_relatorio(dados_log, blocklist, gerar_relatorio_file)

    # Resumo final
    print(cor("─" * 50, "azul"))
    print(cor("  ✅ ANÁLISE CONCLUÍDA", "verde"))
    print(cor("─" * 50, "azul"))
    print(f"  {resultado['total_consultas']} consultas analisadas")
    print(f"  {resultado['bloqueados']} anúncios bloqueados")
    print(f"  Taxa de bloqueio: {resultado['taxa_bloqueio']}")
    print()


if __name__ == "__main__":
    main()
