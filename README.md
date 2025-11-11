# 📘 Kea_IPAM_Sync

Sincronização automática de reservas DHCP entre **phpIPAM** e **Kea DHCP**.
Agora o projeto oferece dois modos de sincronização:

- `mysql_kea_ipam_sync.py`: grava diretamente na tabela `hosts` do banco MySQL usado pelo Kea.
- `json_kea_ipam_sync.py`: gera/atualiza um arquivo `kea-dhcp4.conf`, ideal para ambientes como o **pfSense** que usam o Kea com backend em arquivo JSON.

## 🚀 Visão Geral
- Consulta endereços no **phpIPAM** marcados com o campo custom `kea_reserve`.
- Permite sincronizar de duas formas:
  - **MySQL**: realiza operações `INSERT`, `UPDATE` e `DELETE` na tabela `hosts` do Kea (via `mysql_kea_ipam_sync.py`).
  - **JSON**: escreve as reservas dentro de um `kea-dhcp4.conf` compatível com o Kea/pfSense (via `json_kea_ipam_sync.py`).
- Suporta execução periódica via **Cron**, garantindo sincronização contínua.
- Mantém o Kea DHCP alinhado ao estado desejado do IPAM, seja via banco ou arquivo.

---

## 🛠️ Funcionalidades
- **De-duplicação por identificador**: client-id tem prioridade; o último registro válido prevalece.
- **Reload opcional**: suporta envio de `config-reload` ao **Control Agent** após alterações (ativado via `RELOAD_AFTER_DB=true`).
- **Mapeamento flexível de sub-redes**:
  - `SUBNET_ID_MAP_JSON={"39":188}`
  - ou `IPAM_SUBNETID_TO_ID=39:188`
- **Compatível com phpIPAM 1.7.3** (evita endpoints `search` problemáticos por padrão).
- **Logs**: armazena logs da execução do script, preservando os últimos 5 dias de execução.
- **Modo MySQL**: aplica upsert inteligente em três etapas e remove reservas órfãs do banco quando habilitado.
- **Modo JSON**: gera um `kea-dhcp4.conf` com reservas atualizadas, mantendo a interface web do pfSense utilizável para consulta.

---

## 📂 Estrutura do Projeto
```
kea_ipam_sync/
├── mysql_kea_ipam_sync.py  # Sincronização com banco MySQL do Kea
├── json_kea_ipam_sync.py   # Sincronização gerando arquivo kea-dhcp4.conf
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
```

### Exemplo de `.env`:

```ini
# --- phpIPAM ---
PHPIPAM_BASE_URL=https://ipam.seu.local/
PHPIPAM_APP_ID=kea-sync
# Se tiver token estático:
PHPIPAM_TOKEN=
# Ou use usuário/senha (comente o token):
# PHPIPAM_USERNAME=apiuser
# PHPIPAM_PASSWORD=apipass
PHPIPAM_VERIFY_TLS=false

CUSTOM_FIELD_NAME=custom_kea_reserve
CUSTOM_FIELD_TRUE_VALUES=1,true,yes,sim,on

# --- Modo MySQL ---
KEA_DB_HOST=
KEA_DB_PORT=3306
KEA_DB_NAME=kea
KEA_DB_USER=kea
KEA_DB_PASS=

# --- Modo JSON ---
KEA_JSON_OUTPUT_PATH=/usr/local/etc/kea/kea-dhcp4.conf
# Opcional: usar um template estático como base
# KEA_JSON_TEMPLATE_PATH=/usr/local/etc/kea/kea-dhcp4.template

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
```

### Execução automática (Cron)
Adicione em `crontab -e` para 5 minutos (ajuste o script conforme o modo desejado):
```cron
*/5 * * * * cd /caminho/Kea_IPAM_Sync && /caminho/Kea_IPAM_Sync/venv/bin/python mysql_kea_ipam_sync.py --env /caminho/Kea_IPAM_Sync/.env
# ou
*/5 * * * * cd /caminho/Kea_IPAM_Sync && /caminho/Kea_IPAM_Sync/venv/bin/python json_kea_ipam_sync.py --env /caminho/Kea_IPAM_Sync/.env
```

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

