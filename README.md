# 🛡️ TermuxNetShield

**Sistema de bloqueio de anúncios via DNS para Termux (Android)**

Transforma seu celular Android em um bloqueador de anúncios a nível de DNS usando um servidor DNS em Python puro. Bloqueia anúncios e rastreadores em **todos os apps** e no sistema inteiro.

---

## 📋 Índice

- [Como funciona](#-como-funciona)
- [Instalação](#-instalação)
- [Uso (CLI)](#-uso-cli)
- [Comandos disponíveis](#-comandos-disponíveis)
- [Arquitetura do projeto](#-arquitetura-do-projeto)
- [Whitelist](#-whitelist)
- [Análise de logs](#-análise-de-logs)
- [Configurar DNS no Android](#-configurar-dns-no-android-sem-root)
- [Exemplos rápidos](#-exemplos-rápidos)
- [Perguntas frequentes](#-perguntas-frequentes)

---

## 🧠 Como funciona

1. O **servidor DNS em Python** (`dns_server.py`) roda no Termux na porta 5353
2. Toda consulta DNS do seu dispositivo passa por ele
3. Se o domínio estiver na **blocklist** (~745k domínios de ads, trackers, malware e miners), ele responde com `0.0.0.0` — ou seja, **bloqueia a conexão**
4. Se for um domínio legítimo, encaminha para Cloudflare (1.1.1.1) ou Google (8.8.8.8)
5. Você controla tudo via um único comando: **`shield`**

```
App → DNS Query → shield start (127.0.0.1:5353)
                    │
                  ├─ Na blocklist? → 0.0.0.0 🛡️
                  │
                  ├─ Na whitelist? → 1.1.1.1 ✅ (nunca bloqueia)
                  │
                  └─ Limpo? → 1.1.1.1 → Resposta
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

# 2. Execute o instalador (uma vez)
shield install
```

O `shield install` faz automaticamente:

1. ✅ Atualiza pacotes do Termux
2. ✅ Instala dependências (Python, curl, dnslib)
3. ✅ Cria diretórios (`logs/`, `blocklists/`, `config/`, `relatorios/`)
4. ✅ Baixa a blocklist inicial
5. ✅ Adiciona o diretório do projeto ao PATH (recarregue o shell)

> Após instalar, **recarregue o shell** ou execute `source ~/.bashrc`
> para usar `shield` de qualquer diretório.

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
├── shield.py              # 🆕 CLI unificada (tudo num comando)
├── shield                  # Wrapper bash: delega para shield.py
│
├── install.sh              # (legado — use shield install)
├── start.sh                # (legado — use shield start)
├── stop.sh                 # (legado — use shield stop)
├── update-blocklist.sh     # (legado — use shield update)
│
├── config/
│   ├── dnsmasq.conf        # Configuração (legado)
│   ├── whitelist.txt       # 🆕 Domínios liberados manualmente
│   └── custom_blocklist.txt# 🆕 Domínios extras para bloquear
│
├── scripts/
│   ├── dns_server.py       # Servidor DNS bloqueador (Python + dnslib)
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
└── README.md               # Este arquivo
```

---

## 📋 Whitelist

Nem todo domínio bloqueado é um anúncio indesejado. Se um site ou app parar de funcionar, você pode liberar domínios específicos.

### Adicionar à whitelist

```bash
shield whitelist add doubleclick.net
```

Isso adiciona `doubleclick.net` ao arquivo `config/whitelist.txt`.
O servidor DNS **nunca bloqueará** domínios na whitelist — mesmo que estejam na blocklist.

### Listar whitelist

```bash
shield whitelist list
```

### Remover da whitelist

```bash
shield whitelist remove doubleclick.net
```

### Aplicar mudanças

Após alterar a whitelist enquanto o servidor está rodando:

```bash
shield reload
```

(O servidor recarrega a whitelist em tempo real via SIGHUP — sem reiniciar.)

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

### Quantos domínios são bloqueados?

A blocklist tem **~745.000 domínios** (após dedup de 6 fontes),
incluindo redes de anúncio, rastreadores, malware, phishing, mineradores e telemetria.

### O servidor DNS consome muita bateria?

Não. O servidor usa ~10-15 MB de RAM e praticamente zero de CPU quando ocioso.

### Como desinstalar?

```bash
shield uninstall
```

Isso para o servidor, remove os arquivos e limpa o PATH do .bashrc.

---

## 📄 Licença

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
O servidor agora rastreia quantas consultas cada IP fez (visível nos logs).

### 📋 Comandos novos
```
shield config set mode <light|medium|hard>
shield start --no-cname-uncloak
```
