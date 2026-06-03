# TermuxNetShield v2.0 - Pi-hole Style

Uma versão completa do **TermuxNetShield** com interface web estilo **Pi-hole**, oferecendo bloqueio de anúncios em nível de rede com dashboard interativo e API REST.

## 🚀 Funcionalidades

### Servidor DNS
- ✅ Servidor DNS UDP na porta 5353 (configurável)
- ✅ Bloqueio de anúncios via blocklist (dnsmasq format)
- ✅ Suporte a múltiplas listas: blocklist, whitelist, blacklist
- ✅ CNAME uncloaking para detectar trackers disfarçados
- ✅ Encaminhamento para upstreams (Cloudflare, Google)
- ✅ Recarga de blocklist em tempo real (SIGHUP ou API)
- ✅ Thread-safe com LRU cache para evitar vazamento de memória

### Interface Web (Dashboard)
- 📊 Estatísticas em tempo real:
  - Total de consultas
  - Consultas bloqueadas
  - Consultas permitidas
  - Tamanho da blocklist
- 📈 Top domínios consultados
- 📈 Top clientes por IP
- 📋 Log de queries recentes com status e motivo
- ⚙️ Controles:
  - Ativar/desativar bloqueio
  - Recarregar blocklist
  - Adicionar/remover domínios da whitelist/blacklist

### API REST
Endpoints disponíveis:

| Endpoint | Método | Descrição |
|----------|--------|-----------|
| `/` | GET | Dashboard HTML |
| `/api/stats` | GET | Estatísticas gerais |
| `/api/queries` | GET | Log de queries recentes |
| `/api/top-domains` | GET | Top domínios consultados |
| `/api/top-clients` | GET | Top clientes por IP |
| `/api/querytypes` | GET | Tipos de query (A, AAAA, CNAME, etc) |
| `/api/blocklist/status` | GET | Status do bloqueio |
| `/api/blocklist/enable` | POST | Habilitar bloqueio |
| `/api/blocklist/disable` | POST | Desabilitar bloqueio |
| `/api/blocklist/reload` | POST | Recarregar blocklist |
| `/api/whitelist/add` | POST | Adicionar à whitelist |
| `/api/whitelist/remove` | POST | Remover da whitelist |
| `/api/blacklist/add` | POST | Adicionar à blacklist |
| `/api/blacklist/remove` | POST | Remover da blacklist |

## 📦 Instalação

### 1. Instalar dependências
```bash
pip install dnslib aiohttp aiofiles psutil
```

### 2. Ou usar o script de instalação
```bash
chmod +x install.sh
./install.sh
```

## 🎯 Uso

### Iniciar com script
```bash
./start-pihole.sh
```

### Opções personalizadas
```bash
./start-pihole.sh --dns-port 5353 --web-port 8080
```

### Iniciar manualmente
```bash
python3 scripts/pihole_server.py --dns-port 5353 --web-port 8080
```

### Opções de linha de comando
```
--dns-port PORTA    Porta do servidor DNS (padrão: 5353)
--dns-host HOST     Host do servidor DNS (padrão: 127.0.0.1)
--web-port PORTA    Porta da interface web (padrão: 8080)
--web-host HOST     Host da interface web (padrão: 0.0.0.0)
--verbose           Modo verbose com logs detalhados
--no-cname-uncloak  Desativar CNAME uncloaking
```

## 🔧 Configuração

### Estrutura de diretórios
```
/workspace/
├── scripts/
│   └── pihole_server.py      # Servidor principal
├── blocklists/
│   └── ads.conf              # Blocklist principal
├── config/
│   ├── whitelist.txt         # Domínios permitidos
│   └── blacklist.txt         # Domínios bloqueados extras
├── logs/
│   ├── dns_server.log        # Logs do servidor
│   └── queries.log           # Log de queries (JSON)
└── start-pihole.sh           # Script de inicialização
```

### Formato da Blocklist
O arquivo `blocklists/ads.conf` usa o formato dnsmasq:
```
address=/doubleclick.net/0.0.0.0
address=/googleadservices.com/0.0.0.0
address=/taboola.com/0.0.0.0
```

### Whitelist
Domínios na whitelist nunca são bloqueados, mesmo que estejam na blocklist:
```
meusite.com
api.banco.com.br
```

### Blacklist
Domínios na blacklist têm prioridade máxima de bloqueio:
```
tracker.malicioso.com
ads.indesejados.net
```

## 🌐 Acessando o Dashboard

Após iniciar o servidor, acesse:
```
http://localhost:8080
```

Ou, se estiver em outro dispositivo na rede:
```
http://<IP_DO_SERVIDOR>:8080
```

### Configurando DNS nos dispositivos

#### Android (Wi-Fi)
1. Configurações → Wi-Fi
2. Segure na rede → Modificar rede
3. Avançado → DHCP → Estático
4. DNS 1: `127.0.0.1` (ou IP do servidor)
5. DNS 2: `8.8.8.8` (fallback)

#### Linux
```bash
sudo nano /etc/resolv.conf
nameserver 127.0.0.1
nameserver 8.8.8.8
```

#### Windows
```powershell
netsh interface ip set dns "Ethernet" static 127.0.0.1
netsh interface ip add dns "Ethernet" 8.8.8.8 index=2
```

## 📊 Exemplo de Uso da API

### Obter estatísticas
```bash
curl http://localhost:8080/api/stats
```

Resposta:
```json
{
  "total_queries": 1523,
  "total_blocked": 342,
  "total_allowed": 1181,
  "blocking_active": true,
  "blocklist_total": 721474,
  "whitelist_total": 15,
  "blacklist_total": 8,
  "uptime_seconds": 3600,
  "clients_count": 5
}
```

### Adicionar domínio à blacklist
```bash
curl -X POST http://localhost:8080/api/blacklist/add \
  -H "Content-Type: application/json" \
  -d '{"domain": "ads.exemplo.com"}'
```

### Desativar bloqueio temporariamente
```bash
curl -X POST http://localhost:8080/api/blocklist/disable
```

### Recarregar blocklist
```bash
curl -X POST http://localhost:8080/api/blocklist/reload
```

## 🔒 Segurança

### Recomendações
1. **Não exponha a porta 8080 publicamente** - A interface web não tem autenticação
2. **Use firewall** para restringir acesso à porta DNS
3. **Monitore os logs** regularmente
4. **Mantenha as blocklists atualizadas**

### Firewall (exemplo iptables)
```bash
# Permitir apenas rede local
iptables -A INPUT -p udp --dport 5353 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p udp --dport 5353 -j DROP
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

## 🛠️ Troubleshooting

### Porta 5353 já em uso
```bash
# Use outra porta
python3 scripts/pihole_server.py --dns-port 5354
```

### Permissão negada para porta
Portas abaixo de 1024 requerem root. Use portas >= 1024 ou:
```bash
sudo setcap 'cap_net_bind_service=+ep' $(which python3)
```

### Verificar logs
```bash
tail -f logs/dns_server.log
```

### Testar servidor DNS
```bash
dig @127.0.0.1 -p 5353 google.com
dig @127.0.0.1 -p 5353 doubleclick.net  # Deve retornar 0.0.0.0
```

## 📈 Melhorias em relação à versão anterior

### Correções de falhas
- ✅ Race condition no acesso a dicionários globais resolvida com locks
- ✅ Vazamento de memória prevenido com LRU cache
- ✅ Sockets sempre fechados corretamente com `finally`
- ✅ Handlers de sinal apenas na thread principal
- ✅ Static files verificados antes de registrar

### Novas funcionalidades
- ✅ Interface web completa estilo Pi-hole
- ✅ API REST para automação
- ✅ Blacklist separada da blocklist principal
- ✅ Controle de bloqueio on/off via API
- ✅ Logs de queries com motivo do bloqueio
- ✅ Estatísticas em tempo real no dashboard
- ✅ Adição/remoção de domínios via interface

## 🤝 Contribuindo

Contribuições são bem-vindas! Sinta-se à vontade para:
- Reportar bugs
- Sugerir melhorias
- Enviar pull requests

## 📄 Licença

MIT License - veja o arquivo LICENSE para detalhes.

## 🙏 Créditos

Inspirado no [Pi-hole](https://pi-hole.net/) - Network-wide Ad Blocking
