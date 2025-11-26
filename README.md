# 📘 Kea_IPAM_Sync

Sincronização automática de reservas DHCP entre **phpIPAM** e **Kea DHCP**.
Agora o projeto oferece três modos de sincronização, cada um totalmente independente
e executável de forma isolada (basta manter o script desejado na pasta):

- `mysql_kea_ipam_sync.py`: grava diretamente na tabela `hosts` do banco MySQL usado pelo Kea.
- `json_kea_ipam_sync.py`: gera/atualiza um arquivo `kea-dhcp4.conf`, ideal para ambientes com **Kea DHCP Server** usando o Kea com backend em arquivo JSON.
- `pfsense_kea_ipam_sync.py`: atualiza o `$config` do pfSense (config.xml) por meio de PHP, mantendo a interface web sincronizada.

## 🚀 Visão Geral
- Consulta endereços no **phpIPAM** marcados com o campo custom `kea_reserve`.
- Permite sincronizar de três formas:
  - **MySQL**: realiza operações `INSERT`, `UPDATE` e `DELETE` na tabela `hosts` do Kea (via `mysql_kea_ipam_sync.py`).
  - **JSON**: escreve as reservas dentro de um `kea-dhcp4.conf` compatível com o Kea DHCP (via `json_kea_ipam_sync.py`).
  - **pfSense ($config)**: envia a configuração diretamente para o `config.xml` do pfSense usando `pfsense_kea_ipam_sync.py`.
- Suporta execução periódica via **Cron**, garantindo sincronização contínua.
- Mantém o Kea DHCP alinhado ao estado desejado do IPAM, seja via banco ou arquivo.

---

## 🛠️ Funcionalidades
- **De-duplicação por identificador**: client-id tem prioridade; o último registro válido prevalece.
- **Reload opcional**: após alterar reservas, pode acionar o reload via **Control Agent HTTP** ou executar um comando remoto no pfSense por **SSH** (`RELOAD_AFTER_DB=true`).
- **Mapeamento flexível de sub-redes**:
  - `SUBNET_ID_MAP_JSON={"39":188}`
  - ou `IPAM_SUBNETID_TO_ID=39:188`
- **Compatível com phpIPAM 1.7.3** (evita endpoints `search` problemáticos por padrão).
- **Logs**: armazena logs da execução do script, preservando os últimos 5 dias de execução.
- **Modo MySQL**: aplica upsert inteligente em três etapas e remove reservas órfãs do banco quando habilitado.
- **Modo JSON**: gera um `kea-dhcp4.conf` com reservas atualizadas, mantendo a interface web do pfSense utilizável para consulta.
- **Modo pfSense ($config)**: publica as reservas direto no `config.xml` (via PHP) para que o pfSense enxergue os leases nas telas oficiais.

---

## 📂 Estrutura do Projeto
```
kea_ipam_sync/
├── mysql_kea_ipam_sync.py  # Sincronização com banco MySQL do Kea
├── json_kea_ipam_sync.py   # Sincronização gerando arquivo kea-dhcp4.conf
├── pfsense_kea_ipam_sync.py # Sincronização atualizando o $config do pfSense
├── .env                  # Configurações de ambiente
├── .env.example          # Exemplo de Configurações de ambiente (pronto para copiar)
├── logs/                 # Pasta de logs de execução do projeto
├── README.md             # Documentação do projeto
└── venv/                 # Arquivos de execução Python
```

---

## 📋 Requisitos
- Python 3.8+
- Bibliotecas básicas:
  ```bash
  pip install requests python-dotenv
  ```
- Para o modo MySQL: adicionar `PyMySQL`.
- Servidor phpIPAM com API habilitada.
- Kea DHCP com backend **MySQL** ou **arquivo JSON** (como no pfSense).
- Para integração remota com pfSense: utilitários `ssh/scp` disponíveis no servidor onde o script roda e acesso autorizado ao pfSense.
- Para autenticação por senha no SSH: utilitário `sshpass` instalado **ou** biblioteca Python `paramiko` disponível.

---

## ⚙️ Configuração

### Instalação do ambiente
```bash
cd Kea_IPAM_Sync
python3 -m venv venv
source venv/bin/activate
pip install requests python-dotenv
# Apenas para o modo MySQL:
pip install PyMySQL
# Para autenticação por senha sem sshpass instalado:
# pip install paramiko
```

### Exemplo de `.env`:
Um arquivo `.env.example` já está disponível e cobre as variáveis usadas pelos três
modos; basta copiá-lo e ajustar os valores:

```bash
cp .env.example .env
```

```ini
# =========================================
# Exemplo de configuração para Kea_IPAM_Sync
# Copie este arquivo para `.env` e ajuste os valores
# =========================================

# --- phpIPAM (obrigatório) ----------------------------------------------------
# URL base da API (deve terminar com barra)
PHPIPAM_BASE_URL=https://ipam.seu.local/
# Application ID criado no phpIPAM para o script
PHPIPAM_APP_ID=kea-sync
# Token estático gerado no phpIPAM (opcional)
PHPIPAM_TOKEN=
# Ou, em vez do token, habilite usuário/senha abaixo:
# PHPIPAM_USERNAME=apiuser
# PHPIPAM_PASSWORD=apipass
# Validação do certificado TLS (true/false)
PHPIPAM_VERIFY_TLS=false

# Campo customizado no phpIPAM que marca reservas para o Kea
CUSTOM_FIELD_NAME=custom_kea_reserve
# Valores que serão interpretados como "verdadeiro" para o campo acima
CUSTOM_FIELD_TRUE_VALUES=1,true,yes,sim,on

# --- Conexão MySQL do Kea (opcional) ------------------------------------------
# Obrigatório apenas ao usar mysql_kea_ipam_sync.py
KEA_DB_HOST=
KEA_DB_PORT=3306
KEA_DB_NAME=kea
KEA_DB_USER=kea
KEA_DB_PASS=

# --- Geração de arquivo JSON (json_kea_ipam_sync.py) ---------------------------
# Caminho local (opcional) para salvar o arquivo durante a sincronização.
# O padrão mantém o arquivo na mesma pasta do script.
KEA_JSON_OUTPUT_PATH=kea-dhcp4.conf
# Opcional: usar um template base existente
# KEA_JSON_TEMPLATE_PATH=/usr/local/etc/kea/kea-dhcp4.template

# --- Deploy remoto em pfSense via SSH (opcional) -------------------------------
# Informe o host para habilitar o envio automático do arquivo gerado
PF_SSH_HOST=pfsense.exemplo.local
# Usuário que será usado para conectar via SSH/SCP
PF_SSH_USER=admin
# Senha do usuário acima. Requer `sshpass` instalado ou a biblioteca Python `paramiko`
PF_SSH_PASSWORD=
# Porta SSH (descomente para alterar o padrão 22)
# PF_SSH_PORT=22
# Caminho para chave privada, caso prefira autenticação por chave
# PF_SSH_KEY=/caminho/para/id_rsa
# Caminho do arquivo known_hosts personalizado (opcional)
# PF_SSH_KNOWN_HOSTS=/caminho/para/known_hosts
# Caminho remoto para onde o arquivo JSON será copiado
PF_SSH_REMOTE_PATH=/usr/local/etc/kea/kea-dhcp4.conf
# Comando remoto para aplicar as mudanças sem parar o serviço
# PF_SSH_RELOAD_COMMAND=sudo keactrl reload -s dhcp4
# Defina para "false" para ignorar validação de host key (não recomendado)
# PF_SSH_STRICT_HOST_KEY_CHECKING=true
# Argumentos adicionais para ssh/scp (ex.: jump host)
# PF_SSH_EXTRA_ARGS=-o ProxyCommand="ssh jumphost -W %h:%p"
# Remove o arquivo local temporário após o deploy bem-sucedido
PF_SSH_REMOVE_LOCAL_COPY=false

# Controla se o script executará um reload após atualizar as reservas
RELOAD_AFTER_DB=true

# --- pfSense ($config) --------------------------------------------------------
# Caminho do array $config que armazena a configuração DHCP.
# As reservas são gravadas diretamente em $config['dhcpd'][iface]['staticmap']
# e qualquer caminho diferente será ignorado.
PF_CONFIG_PATH=dhcpd
# Mensagem registrada no config.xml ao aplicar alterações
PF_CONFIG_WRITE_NOTE=Atualizado via Kea_IPAM_Sync

# --- Mapas de subnet-id -------------------------------------------------------
# Exemplo de mapeamento: subnetId do phpIPAM -> subnet-id do Kea
# (no modo pfSense, apenas as chaves são usadas para listar as sub-redes sincronizadas
# e o script descobre automaticamente a interface correspondente no $config)
SUBNET_ID_MAP_JSON={"39":188}
# Alternativa em formato separado por dois pontos (pode listar vários separados por vírgula)
# IPAM_SUBNETID_TO_ID=39:188,40:189

# --- Control Agent HTTP (opcional) --------------------------------------------
# Use apenas quando não estiver enviando para o pfSense via SSH
# KEA_URL=http://127.0.0.1:8000/
# KEA_USER=
# KEA_PASSWORD=

# --- Logs ---------------------------------------------------------------------
# Pasta onde os logs serão gravados (criada automaticamente)
# KEA_IPAM_SYNC_LOG_DIR=logs
# Quantidade de dias de logs a manter
# KEA_IPAM_SYNC_LOG_RETENTION_DAYS=5

# --- Depuração ----------------------------------------------------------------
# Defina como true para habilitar logs detalhados
# DEBUG=false
# DEBUG_ONE_A_ONE=false
```

---

## ▶️ Uso
### Execução manual
```bash
source venv/bin/activate
# Modo MySQL
python3 mysql_kea_ipam_sync.py --dry-run
python3 mysql_kea_ipam_sync.py

# Modo JSON
python3 json_kea_ipam_sync.py --dry-run
python3 json_kea_ipam_sync.py

# Modo pfSense ($config)
python3 pfsense_kea_ipam_sync.py --dry-run
python3 pfsense_kea_ipam_sync.py
```

### Execução automática (Cron)
Adicione em `crontab -e` para 5 minutos (ajuste o script conforme o modo desejado):
```cron
*/5 * * * * cd /caminho/Kea_IPAM_Sync && /caminho/Kea_IPAM_Sync/venv/bin/python mysql_kea_ipam_sync.py --env /caminho/Kea_IPAM_Sync/.env
# ou
*/5 * * * * cd /caminho/Kea_IPAM_Sync && /caminho/Kea_IPAM_Sync/venv/bin/python json_kea_ipam_sync.py --env /caminho/Kea_IPAM_Sync/.env
# ou
*/5 * * * * cd /caminho/Kea_IPAM_Sync && /caminho/Kea_IPAM_Sync/venv/bin/python pfsense_kea_ipam_sync.py --env /caminho/Kea_IPAM_Sync/.env
```

### Execução remota para pfSense
Ao definir `PF_SSH_HOST`, o `json_kea_ipam_sync.py` baixa o `kea-dhcp4.conf` do pfSense via `scp`, atualiza o conteúdo localmente e, em seguida, envia o arquivo de volta com as reservas sincronizadas.
O caminho remoto usado para leitura/escrita é o definido em `PF_SSH_REMOTE_PATH` (ou variáveis equivalentes).
Se desejar descartar o arquivo temporário criado na pasta do script após um deploy bem-sucedido, basta ativar `PF_SSH_REMOVE_LOCAL_COPY=true`.
Com `RELOAD_AFTER_DB=true`, o script também executa o comando configurado em `PF_SSH_RELOAD_COMMAND` (padrão `sudo keactrl reload -s dhcp4`) via SSH para aplicar as mudanças sem interromper o serviço.
Se quiser manter o reload via Control Agent HTTP, basta deixar `PF_SSH_HOST` vazio e configurar `KEA_URL`/`KEA_USER`/`KEA_PASSWORD` normalmente.
Quando `PF_SSH_PASSWORD` estiver definido, o script usa `sshpass` (se disponível) ou, alternativamente, a biblioteca Python `paramiko`. Instale um dos dois métodos para permitir autenticação não interativa por senha.

O `pfsense_kea_ipam_sync.py` reutiliza exatamente essas mesmas variáveis para executar comandos PHP diretamente no firewall. Caso nenhum `PF_SSH_HOST` seja informado, o script supõe que está rodando dentro do próprio pfSense (onde o binário `php` já está presente).

#### Escolhendo o nó no `$config`
O modo pfSense trabalha exclusivamente com `$config['dhcpd']`. Mesmo que `PF_CONFIG_PATH` seja definido com outro caminho (por exemplo, o antigo `installedpackages:kea_dhcp4:...`), o script irá ignorar o valor e usar `dhcpd` automaticamente. Isso evita que as reservas sejam gravadas em árvores que não são consumidas pelo serviço DHCP nativo. Se você migrou de uma versão anterior, basta remover o valor antigo do `.env` ou deixá-lo como `dhcpd`.

Durante a sincronização o script envia ao pfSense apenas as listas de static-maps por interface. Um trecho em PHP (executado localmente ou via SSH) garante que `$config['dhcpd'][$iface]['staticmap']` exista, substitui o conteúdo somente quando há diferenças e, aí sim, chama `write_config()` + `services_dhcpd_configure()`. Caso não haja nenhuma mudança, o pfSense permanece intacto e o reload é pulado.

O `pfsense_kea_ipam_sync.py` também aproveita as chaves configuradas em `SUBNET_ID_MAP_JSON` (ou equivalentes) para buscar as sub-redes no phpIPAM e cruza cada IP com os dados de `$config['interfaces']`. Dessa forma ele descobre automaticamente qual interface DHCP deve receber as reservas, eliminando a necessidade de mapear `lan`, `vlanX` etc. manualmente.

---

## 📝 Notas Importantes
- **Segurança**: evite usar `root` do MySQL. Crie um usuário dedicado só com permissões na tabela `hosts`.
- **Desenvolvimento**: foi utilizado Ubuntu Server 24.04 como SO de hospedagem e execução do script.

---

## 📖 Documentação útil
- [Kea Administrator Reference Manual](https://kea.readthedocs.io/en/latest/)
- [phpIPAM API Documentation](https://phpipam.net/api-documentation/)
- [RFC 2131 - DHCP](https://datatracker.ietf.org/doc/html/rfc2131)

---

