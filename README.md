# 📘 Kea_IPAM_Sync

Sincronização automática de reservas DHCP entre **phpIPAM** e **Kea DHCP**.
Agora o projeto oferece três modos de sincronização:

- `mysql_kea_ipam_sync.py`: grava diretamente na tabela `hosts` do banco MySQL usado pelo Kea.
- `json_kea_ipam_sync.py`: gera/atualiza um arquivo `kea-dhcp4.conf`, ideal para ambientes como o **pfSense** que usam o Kea com backend em arquivo JSON.
- `pfsense_kea_ipam_sync.py`: atualiza o `$config` do pfSense (config.xml) por meio de PHP, mantendo a interface web sincronizada.

## 🚀 Visão Geral
- Consulta endereços no **phpIPAM** marcados com o campo custom `kea_reserve`.
- Permite sincronizar de três formas:
  - **MySQL**: realiza operações `INSERT`, `UPDATE` e `DELETE` na tabela `hosts` do Kea (via `mysql_kea_ipam_sync.py`).
  - **JSON**: escreve as reservas dentro de um `kea-dhcp4.conf` compatível com o Kea/pfSense (via `json_kea_ipam_sync.py`).
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
├── .env.example          # Exemplo de Configurações de ambiente
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

```ini
# --- phpIPAM (obrigatório) ---
PHPIPAM_BASE_URL=https://ipam.seu.local/
PHPIPAM_APP_ID=kea-sync
# Se tiver token estático:
PHPIPAM_TOKEN=
# Ou use usuário/senha (comente o token):
# PHPIPAM_USERNAME=apiuser
# PHPIPAM_PASSWORD=apipass
PHPIPAM_VERIFY_TLS=false

# --- Campo customizado usado para marcar reservas ---
CUSTOM_FIELD_NAME=custom_kea_reserve
CUSTOM_FIELD_TRUE_VALUES=1,true,yes,sim,on

# --- Modo MySQL ---
KEA_DB_HOST=
KEA_DB_PORT=3306
KEA_DB_NAME=kea
KEA_DB_USER=kea
KEA_DB_PASS=

# --- Modo JSON ---
# Caminho local (opcional) para o arquivo gerado durante a sincronização
# (por padrão será criado na pasta do script)
KEA_JSON_OUTPUT_PATH=kea-dhcp4.conf
# Opcional: usar um template estático como base
# KEA_JSON_TEMPLATE_PATH=/usr/local/etc/kea/kea-dhcp4.template

# --- Deploy remoto pfSense via SSH ---
PF_SSH_HOST=pfsense.exemplo.local
PF_SSH_USER=admin
PF_SSH_PASSWORD=
# PF_SSH_PORT=22
# PF_SSH_KEY=/caminho/para/id_rsa
# PF_SSH_KNOWN_HOSTS=/caminho/para/known_hosts
PF_SSH_REMOTE_PATH=/usr/local/etc/kea/kea-dhcp4.conf
# PF_SSH_RELOAD_COMMAND=sudo keactrl reload -s dhcp4
# PF_SSH_STRICT_HOST_KEY_CHECKING=true
# PF_SSH_EXTRA_ARGS=-o ProxyCommand="ssh jumphost -W %h:%p"
PF_SSH_REMOVE_LOCAL_COPY=false
RELOAD_AFTER_DB=true

# --- pfSense ($config) ---
PF_CONFIG_PATH=installedpackages:kea_dhcp4:config:0:Dhcp4
PF_CONFIG_WRITE_NOTE=Atualizado via Kea_IPAM_Sync

# --- Mapeamentos de subnet-id ---
SUBNET_ID_MAP_JSON={"39":188}

# --- (Opcional) Control Agent ---
KEA_URL=
KEA_USER=
KEA_PASSWORD=
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
Defina `PF_CONFIG_PATH` para apontar o caminho até a estrutura que representa o `Dhcp4` (por exemplo `installedpackages:kea_dhcp4:config:0:Dhcp4`). Use dois pontos (`:`) para separar cada nível do array `$config`. O script lê esse nó antes de aplicar qualquer alteração, compara com o que veio do phpIPAM e só executa `write_config()` + `services_kea_*_configure()` quando detectar um `update`. Se nada mudar, apenas um log é emitido e o reload é pulado.

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

