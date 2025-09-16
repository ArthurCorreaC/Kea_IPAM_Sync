# 📘 Kea_IPAM_Sync

Sincronização automática de reservas DHCP entre **phpIPAM** e **Kea DHCP**.  
O script conecta-se ao **MySQL do Kea** e utiliza a **API do phpIPAM** para garantir que os hosts com um campo customizado específico (`kea_reserve`) estejam refletidos corretamente no banco do Kea.

## 🚀 Visão Geral
- Consulta endereços no **phpIPAM** marcados com o campo custom `kea_reserve`.
- Realiza operações de **CRUD** diretamente na tabela `hosts` do banco de dados do Kea:
  - `INSERT` (incluir nova reserva);
  - `UPDATE` (alterar IP, MAC ou hostname);
  - `DELETE` (quando habilitado, para limpar reservas órfãs – opcional via GC).
- Suporta execução periódica via **Cron**, garantindo sincronização contínua.
- Mantém o Kea DHCP alinhado ao estado desejado do IPAM.

---

## 🛠️ Funcionalidades
- **Upsert inteligente (Patch 4)**: evita erros de chave duplicada (`1062 Duplicate entry`) usando lógica em três etapas:
  1. `UPDATE` por MAC (`dhcp_identifier`);
  2. `UPDATE` por `(subnet_id + IP)` trocando o MAC;
  3. `INSERT ... ON DUPLICATE KEY UPDATE`.
- **De-duplicação por MAC**: se múltiplas entradas com o mesmo MAC existirem no IPAM, apenas a última prevalece.
- **Reload opcional**: suporta envio de `config-reload` ao **Control Agent**, mas desativado por padrão, já que o Kea lê reservas do banco em tempo real.
- **Mapeamento flexível de sub-redes**:
  - `SUBNET_ID_MAP_JSON={"39":188}`
  - ou `IPAM_SUBNETID_TO_ID=39:188`
- **Compatível com phpIPAM 1.7.3** (evita endpoints `search` problemáticos por padrão).
- **GC opcional (garbage collect)**: pode ser habilitado para remover reservas no Kea que não estejam mais no IPAM.
- **Logs**: armazena logs da execução do script, preservando os últimos 5 dias de execução. 

---

## 📂 Estrutura do Projeto
```
kea_ipam_sync/
├── kea_ipam_sync.py      # Script principal de sincronização
├── .env                  # Configurações de ambiente
├── .env.example          # Exemplo de Configurações de ambiente
├── logs/                 # Pasta de logs de execução do projeto 
├── README.md             # Documentação do projeto
└── venv/                 # Arquivos de execução Python
```

---

## 📋 Requisitos
- Python 3.8+
- Bibliotecas:
  ```bash
  pip install requests PyMySQL python-dotenv
  ```
- Servidor phpIPAM com API habilitada.
- Kea DHCP com backend **MySQL** configurado.

---

## ⚙️ Configuração

### Instalação do ambiente
```bash
cd Kea_IPAM_Sync
python3 -m venv venv
source venv/bin/activate
pip install requests PyMySQL python-dotenv
```

### Exemplo de `.env`:

```ini
# --- MODO ---
MODE=db

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

# --- Kea DB ---
KEA_DB_HOST=
KEA_DB_PORT=3306
KEA_DB_NAME=kea
KEA_DB_USER=kea
KEA_DB_PASS=

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
python3 kea_ipam_sync.py --dry-run   # apenas simula
python3 kea_ipam_sync.py             # aplica mudanças
```

### Execução automática (Cron)
Adicione em `crontab -e` para 5 minutos:
```cron
*/5 * * * * cd /caminho/Kea_IPAM_Sync && /caminho/Kea_IPAM_Sync/venv/bin/python kea_ipam_sync.py --env /caminho/Kea_IPAM_Sync/.env
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

