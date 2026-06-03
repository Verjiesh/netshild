# 🛡️ TermuxNetShield v2.0 - Pi-hole Edition

**Sistema de bloqueio de anúncios via DNS com Interface Web estilo Pi-hole para Termux (Android)**

Transforma seu celular Android em um bloqueador de anúncios a nível de DNS completo com **dashboard web**, **API REST** e **controle em tempo real**. Bloqueia anúncios e rastreadores em **todos os apps** e no sistema inteiro.

🆕 **NOVIDADE**: Interface web completa igual ao Pi-hole! Acesse `http://localhost:8080` para ver estatísticas, gerenciar blocklists e controlar o servidor.

---

## 📋 Índice

- [Novidades v2.0 - Pi-hole Style](#-novidades-v20---pi-hole-style)
- [Como funciona](#-como-funciona)
- [Instalação](#-instalação)
- [Interface Web (Dashboard)](#-interface-web-dashboard)
- [API REST](#-api-rest)
- [Uso (CLI)](#-uso-cli)
- [Comandos disponíveis](#-comandos-disponíveis)
- [Arquitetura do projeto](#-arquitetura-do-projeto)
- [Whitelist/Blacklist](#-whitelistblacklist)
- [Análise de logs](#-análise-de-logs)
- [Configurar DNS no Android](#-configurar-dns-no-android-sem-root)
- [Exemplos rápidos](#-exemplos-rápidos)
- [Perguntas frequentes](#-perguntas-frequentes)

---

## 🆕 Novidades v2.0 - Pi-hole Style

### 🌐 Interface Web Completa
Agora você tem um **dashboard web** igual ao Pi-hole para controlar tudo:

- 📊 **Estatísticas em tempo real**: queries totais, bloqueios, permits, taxa de bloqueio
- 📈 **Top domínios e clientes**: veja quem mais consulta e quais domínios são mais acessados
- 📋 **Log de queries**: acompanhe todas as consultas com motivo do bloqueio
- ⚙️ **Controle total**: ativar/desativar bloqueio, recarregar blocklist sem reiniciar
- ➕ **Gerenciamento fácil**: adicionar/remover domínios da whitelist/blacklist via interface

**Acesso**: `http://localhost:8080` (ou a porta que configurar)

### 🔌 API REST Completa
14 endpoints para automação e integração:

| Endpoint | Método | Descrição |
|----------|--------|-----------|
| `/api/stats` | GET | Estatísticas gerais |
| `/api/queries` | GET | Log de queries (últimas 1000) |
| `/api/top-domains` | GET | Top 50 domínios consultados |
| `/api/top-clients` | GET | Top 50 clientes por IP |
| `/api/blocklist/enable` | POST | Ativar bloqueio |
| `/api/blocklist/disable` | POST | Desativar bloqueio |
| `/api/blocklist/status` | GET | Status do bloqueio |
| `/api/blocklist/reload` | POST | Recarregar blocklists |
| `/api/whitelist/list` | GET | Listar whitelist |
| `/api/whitelist/add` | POST | Adicionar à whitelist |
| `/api/whitelist/remove` | POST | Remover da whitelist |
| `/api/blacklist/list` | GET | Listar blacklist |
| `/api/blacklist/add` | POST | Adicionar à blacklist |
| `/api/blacklist/remove` | POST | Remover da blacklist |

### 🔧 Melhorias Técnicas
- ✅ **Thread-safe**: locks para acesso concorrente seguro
- ✅ **LRU Cache**: evita vazamento de memória (máx 1000 clientes)
- ✅ **Sockets seguros**: fechamento correto em finally
- ✅ **Handlers de sinal**: apenas na thread principal
- ✅ **Validação de arquivos**: static files verificados antes de registrar

---

## 🧠 Como funciona

1. O **servidor DNS em Python** (`pihole_server.py`) roda no Termux na porta 5353 (DNS) e 8080 (Web)
2. Toda consulta DNS do seu dispositivo passa por ele
3. Se o domínio estiver na **blocklist** (~745k domínios de ads, trackers, malware e miners), ele responde com `0.0.0.0` — ou seja, **bloqueia a conexão**
4. Se for um domínio legítimo, encaminha para Cloudflare (1.1.1.1) ou Google (8.8.8.8)
5. Você controla tudo via **interface web** (`http://localhost:8080`) ou CLI: **`shield`**

```
App → DNS Query → pihole_server (127.0.0.1:5353)
                    │
                  ├─ Na blocklist? → 0.0.0.0 🛡️
                  │
                  ├─ Na whitelist? → 1.1.1.1 ✅ (nunca bloqueia)
                  │
                  └─ Limpo? → 1.1.1.1 → Resposta

Dashboard Web ← http://localhost:8080 (estatísticas, controle, logs)
```

---

## ✅ Pré-requisitos

- **Android 8+** (recomendado)
- **Termux** instalado (da [F-Droid](https://f-droid.org/packages/com.termux/) — **não** da Play Store)
- **Conexão com internet** (para baixar dependências e blocklists)

> ⚠️ Projetado para funcionar **sem root**. Para bloqueio em todo o sistema, use um app de proxy DNS ou iptables (com root).

---

## 📦 Instalação

```bash
# 1. Entre no diretório do projeto
cd ~/TermuxNetShield

# 2. Instale as dependências Python necessárias
pip install dnslib aiohttp

# 3. Execute o instalador (uma vez)
shield install
```

O `shield install` faz automaticamente:

1. ✅ Atualiza pacotes do Termux
2. ✅ Instala dependências (Python, curl, dnslib, aiohttp)
3. ✅ Cria diretórios (`logs/`, `blocklists/`, `config/`, `relatorios/`)
4. ✅ Baixa a blocklist inicial
5. ✅ Adiciona o diretório do projeto ao PATH (recarregue o shell)

> Após instalar, **recarregue o shell** ou execute `source ~/.bashrc`
> para usar `shield` de qualquer diretório.

### Inicialização Rápida

```bash
# Iniciar servidor DNS + Interface Web
./start-pihole.sh

# Ou com portas personalizadas
python3 scripts/pihole_server.py --dns-port 5353 --web-port 8080
```

---

## 🌐 Interface Web (Dashboard)

Acesse `http://localhost:8080` no seu navegador para usar o dashboard completo.

### Funcionalidades do Dashboard

#### 📊 Visão Geral
- **Total de Queries**: Número total de consultas DNS processadas
- **Bloqueios**: Quantos anúncios/trackers foram bloqueados
- **Permitidos**: Consultas para domínios legítimos
- **Taxa de Bloqueio**: Percentual de tráfego bloqueado
- **Status**: Indicador visual se o bloqueio está ativo ou não

#### 📈 Gráficos e Estatísticas
- **Top Domínios**: Os 50 domínios mais consultados
- **Top Clientes**: Os 50 IPs que mais fizeram consultas
- **Queries por Hora**: Distribuição temporal das consultas

#### 📋 Log de Queries em Tempo Real
- Visualize todas as consultas DNS conforme acontecem
- Filtros por tipo (bloqueado/permitido)
- Detalhes: domínio, cliente, motivo do bloqueio

#### ⚙️ Painel de Controle
- **Ativar/Desativar Bloqueio**: Liga/desliga o filtro sem reiniciar
- **Recarregar Blocklist**: Atualiza as listas de domínios bloqueados
- **Estatísticas**: Resummo rápido do sistema

#### ➕ Gerenciamento de Listas
- **Whitelist**: Adicione domínios que nunca devem ser bloqueados
- **Blacklist**: Adicione domínios extras para bloquear
- Interface simples com busca e remoção fácil

### Exemplo de Uso da Interface

1. Abra `http://localhost:8080` no navegador
2. Veja as estatísticas em tempo real no dashboard
3. Clique em "Query Log" para ver consultas recentes
4. Use "Whitelist" ou "Blacklist" para gerenciar domínios
5. Ative/desative o bloqueio com um clique

---

## 🔌 API REST

O TermuxNetShield fornece uma API REST completa para automação e integração.

### Endpoints Disponíveis

#### Estatísticas

```bash
# Estatísticas gerais
curl http://localhost:8080/api/stats

# Retorna:
{
  "total_queries": 1247,
  "blocked_queries": 342,
  "permitted_queries": 905,
  "blocking_active": true,
  "blocklist_size": 745000,
  "whitelist_size": 12
}
```

#### Logs e Consultas

```bash
# Últimas 1000 queries
curl http://localhost:8080/api/queries

# Top domínios consultados
curl http://localhost:8080/api/top-domains

# Top clientes por IP
curl http://localhost:8080/api/top-clients
```

#### Controle de Bloqueio

```bash
# Desativar bloqueio temporariamente
curl -X POST http://localhost:8080/api/blocklist/disable

# Ativar bloqueio novamente
curl -X POST http://localhost:8080/api/blocklist/enable

# Verificar status
curl http://localhost:8080/api/blocklist/status

# Recarregar blocklists sem reiniciar
curl -X POST http://localhost:8080/api/blocklist/reload
```

#### Gerenciamento de Whitelist

```bash
# Listar whitelist
curl http://localhost:8080/api/whitelist/list

# Adicionar domínio
curl -X POST http://localhost:8080/api/whitelist/add \
  -H "Content-Type: application/json" \
  -d '{"domain": "exemplo.com"}'

# Remover domínio
curl -X POST http://localhost:8080/api/whitelist/remove \
  -H "Content-Type: application/json" \
  -d '{"domain": "exemplo.com"}'
```

#### Gerenciamento de Blacklist

```bash
# Listar blacklist
curl http://localhost:8080/api/blacklist/list

# Adicionar domínio
curl -X POST http://localhost:8080/api/blacklist/add \
  -H "Content-Type: application/json" \
  -d '{"domain": "ads.exemplo.com"}'

# Remover domínio
curl -X POST http://localhost:8080/api/blacklist/remove \
  -H "Content-Type: application/json" \
  -d '{"domain": "ads.exemplo.com"}'
```

### Integração com Scripts

Você pode usar a API em scripts bash, Python, ou qualquer linguagem:

```python
import requests

# Verificar estatísticas
stats = requests.get('http://localhost:8080/api/stats').json()
print(f"Bloqueios: {stats['blocked_queries']}")

# Adicionar à whitelist
requests.post('http://localhost:8080/api/whitelist/add',
              json={'domain': 'meusite.com'})
```

---

## 🚀 Uso (CLI)

Tudo se faz com um único comando: **`shield`**

```bash
shield start     # Iniciar bloqueio
shield stop      # Parar bloqueio
shield status    # Ver status
shield logs -f   # Acompanhar bloqueios ao vivo
```

### Comandos disponíveis

#### Gerenciamento

| Comando | Descrição |
|---------|-----------|
| `shield install` | Instalar dependências e configurar projeto |
| `shield uninstall` | Remover completamente o projeto |

#### Serviço DNS

| Comando | Descrição |
|---------|-----------|
| `shield start` | Iniciar servidor DNS na porta 5353 |
| `shield stop` | Parar servidor DNS (com estatísticas) |
| `shield restart` | Reiniciar servidor DNS |
| `shield status` | Status detalhado (PID, consultas, taxa de bloqueio) |
| `shield reload` | Recarregar blocklist sem reiniciar (SIGHUP) |

#### Blocklist

| Comando | Descrição |
|---------|-----------|
| `shield update` | Baixar e atualizar blocklist de 6 fontes |
| `shield whitelist list` | Listar domínios na whitelist |
| `shield whitelist add <dom>` | Adicionar domínio à whitelist |
| `shield whitelist remove <dom>` | Remover domínio da whitelist |

#### Análise e logs

| Comando | Descrição |
|---------|-----------|
| `shield analyze` | Relatório completo de consultas DNS |
| `shield analyze --report` | Salvar relatório em arquivo |
| `shield analyze --clear` | Limpar arquivo de log |
| `shield stats` | Estatísticas rápidas (últimas 5000 linhas) |
| `shield logs` | Últimas 50 linhas do log |
| `shield logs -f` | Logs ao vivo (tail -f) |

#### Configuração

| Comando | Descrição |
|---------|-----------|
| `shield config` | Mostrar configuração e caminhos do projeto |
| `shield help` | Mostrar ajuda completa |

---

## 📁 Arquitetura do projeto

```
TermuxNetShield/
│
├── shield.py              # CLI unificada (tudo num comando)
├── shield                  # Wrapper bash: delega para shield.py
├── start-pihole.sh        # 🆕 Script de inicialização do servidor Pi-hole
│
├── install.sh              # (legado — use shield install)
├── start.sh                # (legado — use shield start)
├── stop.sh                 # (legado — use shield stop)
├── update-blocklist.sh     # (legado — use shield update)
│
├── config/
│   ├── dnsmasq.conf        # Configuração (legado)
│   ├── whitelist.txt       # Domínios liberados manualmente
│   ├── blacklist.txt       # 🆕 Domínios extras para bloquear
│   └── custom_blocklist.txt# Domínios extras para bloquear (legado)
│
├── scripts/
│   ├── pihole_server.py    # 🆕 Servidor DNS + Interface Web (Python + dnslib + aiohttp)
│   ├── dns_server.py       # Servidor DNS bloqueador (legado)
│   └── analyzer.py         # Analisador de logs (legado — use shield analyze)
│
├── logs/
│   └── dns_server.log      # Logs do servidor DNS
│
├── blocklists/
│   └── ads.conf            # Blocklist (~745k domínios)
│
├── relatorios/             # Relatórios de análise (shield analyze --report)
│
├── README.md               # Este arquivo
└── README_PIHOLE.md        # 🆕 Documentação específica da versão Pi-hole
```

---

## 📋 Whitelist/Blacklist

### Whitelist (Domínios Liberados)

Nem todo domínio bloqueado é um anúncio indesejado. Se um site ou app parar de funcionar, você pode liberar domínios específicos.

#### Adicionar à whitelist

**Via CLI:**
```bash
shield whitelist add doubleclick.net
```

**Via API:**
```bash
curl -X POST http://localhost:8080/api/whitelist/add \
  -H "Content-Type: application/json" \
  -d '{"domain": "doubleclick.net"}'
```

Isso adiciona `doubleclick.net` ao arquivo `config/whitelist.txt`.
O servidor DNS **nunca bloqueará** domínios na whitelist — mesmo que estejam na blocklist.

#### Listar whitelist

**Via CLI:**
```bash
shield whitelist list
```

**Via API:**
```bash
curl http://localhost:8080/api/whitelist/list
```

#### Remover da whitelist

**Via CLI:**
```bash
shield whitelist remove doubleclick.net
```

**Via API:**
```bash
curl -X POST http://localhost:8080/api/whitelist/remove \
  -H "Content-Type: application/json" \
  -d '{"domain": "doubleclick.net"}'
```

### Blacklist (Domínios Extras para Bloquear)

Adicione domínios personalizados que deseja bloquear além da blocklist padrão.

#### Adicionar à blacklist

**Via CLI:**
```bash
shield blacklist add ads.exemplo.com
```

**Via API:**
```bash
curl -X POST http://localhost:8080/api/blacklist/add \
  -H "Content-Type: application/json" \
  -d '{"domain": "ads.exemplo.com"}'
```

#### Listar blacklist

**Via CLI:**
```bash
shield blacklist list
```

**Via API:**
```bash
curl http://localhost:8080/api/blacklist/list
```

#### Remover da blacklist

**Via CLI:**
```bash
shield blacklist remove ads.exemplo.com
```

**Via API:**
```bash
curl -X POST http://localhost:8080/api/blacklist/remove \
  -H "Content-Type: application/json" \
  -d '{"domain": "ads.exemplo.com"}'
```

### Aplicar mudanças

Após alterar a whitelist/blacklist enquanto o servidor está rodando:

```bash
shield reload
```

(O servidor recarrega as listas em tempo real via sinal — sem reiniciar.)

> 💡 A whitelist tem precedência **total** sobre a blocklist.
> Se um domínio estiver em ambas, ele será liberado.

---

## 📊 Análise de logs

```bash
shield analyze
```

Gera um relatório completo das consultas DNS:

| Métrica | Descrição |
|---------|-----------|
| 📊 Consultas totais | Quantas consultas DNS foram feitas |
| 🛡️ Bloqueios | Quantos anúncios/trackers foram bloqueados |
| ✅ Liberados | Consultas para domínios legítimos |
| 📈 Taxa de bloqueio | Percentual de tráfego bloqueado |
| 🏆 Top 10 | Domínios mais consultados |
| 🚫 Top bloqueios | Domínios bloqueados com mais frequência |

```bash
shield analyze --report   # Salva relatório em relatorios/
shield analyze --clear    # Limpa o arquivo de log
shield stats              # Estatísticas rápidas
```

### Exemplo de saída:

```
══════════════════════════════════════════
  RELATÓRIO DE ANÁLISE DNS
══════════════════════════════════════════

📊 INFORMAÇÕES GERAIS
  Total consultas:     1,247
  Domínios únicos:     389
  Bloqueados 🛡️:      342
  Liberados ✅:        905
  Taxa de bloqueio:   27.4%

🏆 TOP 10 MAIS CONSULTADOS
   1. google.com                                   187x
   2. doubleclick.net                              89x  🛡️
   3. googleads.g.doubleclick.net                  67x  🛡️
  ...
```

---

## 🌐 Configurar DNS no Android (sem root)

Para o bloqueio funcionar em **todos os apps**, o Android precisa usar o servidor DNS do Termux.

### Opção 1: DNS manual no WiFi

1. Acesse **Configurações → Wi-Fi**
2. Toque na rede atual → **Modificar rede** → **Opções avançadas**
3. Defina **IP como Estático**
4. DNS 1: `127.0.0.1`

### Opção 2: App de proxy DNS (recomendado)

Use apps como:
- **[PersonalDNSfilter](https://f-droid.org/packages/dnsfilter.android/)** (F-Droid, grátis)
- **[NetGuard](https://github.com/M66B/NetGuard)** (com DNS)
- **[RethinkDNS](https://rethinkdns.com/)**

Configure o upstream DNS como `127.0.0.1:5353`.

### Opção 3: iptables (com root)

```bash
su -c "iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 5353"
```

---

## 🎯 Exemplos rápidos

```bash
# Instalação
shield install

# Iniciar bloqueio
shield start

# Ver status
shield status

# Acompanhar bloqueios ao vivo
shield logs -f

# Desbloquear um domínio específico
shield whitelist add googleads.g.doubleclick.net
shield reload

# Atualizar blocklist
shield update

# Ver estatísticas
shield analyze

# Parar
shield stop
```

### Recarregar blocklist sem reiniciar

```bash
shield update && shield reload
```

### Atalho (após adicionar ao PATH)

```bash
# De qualquer diretório:
shield status
shield logs -f
```

---

## ❓ Perguntas frequentes

### Por que a porta 5353 e não 53?

Portas < 1024 exigem root no Linux/Android. A porta 5353 é não-privilegiada e funciona no Termux sem root.

A porta web padrão é 8080, mas pode ser alterada com `--web-port`.

### Quantos domínios são bloqueados?

A blocklist tem **~745.000 domínios** (após dedup de 6 fontes),
incluindo redes de anúncio, rastreadores, malware, phishing, mineradores e telemetria.

### O servidor DNS consome muita bateria?

Não. O servidor usa ~10-15 MB de RAM e praticamente zero de CPU quando ocioso.

A interface web adiciona ~5-10 MB extras de RAM.

### Como desinstalar?

```bash
shield uninstall
```

Isso para o servidor, remove os arquivos e limpa o PATH do .bashrc.

### Posso usar em outros dispositivos na rede?

Sim! Configure o servidor para escutar em `0.0.0.0` e aponte outros dispositivos para o IP do seu celular:

```bash
python3 scripts/pihole_server.py --dns-ip 0.0.0.0 --dns-port 5353
```

Depois configure o DNS manual nos outros dispositivos para `<IP_DO_CELULAR>:5353`.

### A interface web funciona remotamente?

Sim! Use `--web-ip 0.0.0.0` para permitir acesso de outros dispositivos:

```bash
python3 scripts/pihole_server.py --web-ip 0.0.0.0 --web-port 8080
```

Acesse via `http://<IP_DO_CELULAR>:8080`.

---

## 🆕 Novidades da v2.0 - Pi-hole Edition

### 🌐 Interface Web Completa
Dashboard estilo Pi-hole com estatísticas em tempo real, log de queries, gerenciamento de listas e controle total do servidor.

### 🔌 API REST
14 endpoints para automação e integração com scripts e aplicativos.

### 🔧 Melhorias Técnicas
- ✅ **Thread-safe**: locks para acesso concorrente seguro
- ✅ **LRU Cache**: evita vazamento de memória (máx 1000 clientes)
- ✅ **Sockets seguros**: fechamento correto em finally
- ✅ **Handlers de sinal**: apenas na thread principal

---

## 🆕 Novidades da v2.1 (CLI)

MIT — use, modifique e compartilhe livremente.

---

|<p align="center">
  <b>Feito com 💙 para um Android livre de anúncios</b><br>
  <i>TermuxNetShield 🛡️ — CLI v2.1</i>
</p>

---

## 🆕 Novidades da v2.1

### 🛡️ CNAME Uncloaking
Muitos trackers modernos usam registros CNAME para disfarçar o verdadeiro destino:
```
analytics.banco.com  →  CNAME  →  tracker.ads-service.com
```
O TermuxNetShield agora **resolve a cadeia CNAME** de domínios não-bloqueados e verifica se o destino final está na blocklist. **Ativado por padrão** — detecta trackers que outros bloqueadores DNS perdem.

Para desativar (economiza bateria): `shield start --no-cname-uncloak`

### 📊 Modos de bloqueio (tiered blocking)
Inspirado no uBlock Origin, agora você escolhe o nível de proteção:

| Modo | Domínios | Descrição |
|------|----------|-----------|
| `light` | ~300K | Leve, baixo impacto |
| `medium` | ~1.5M | Equilíbrio (padrão) |
| `hard` | ~3M+ | Máxima proteção |

```
shield config set mode hard   # Mudar para modo agressivo
shield update                  # Baixar novas blocklists
shield reload                  # Aplicar sem reiniciar
```

### 👁️ Estatísticas por cliente
O servidor agora rastreia quantas consultas cada IP fez (visível nos logs e na interface web).

### 📋 Comandos novos
```
shield config set mode <light|medium|hard>
shield start --no-cname-uncloak
```

---

## 📄 Licença

MIT — use, modifique e compartilhe livremente.

---

<p align="center">
  <b>Feito com 💙 para um Android livre de anúncios</b><br>
  <i>TermuxNetShield 🛡️ — v2.0 Pi-hole Edition + v2.1 CLI</i>
</p>
