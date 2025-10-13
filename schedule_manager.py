#!/usr/bin/env python3
import os
import json
from datetime import date
import logging
import ldap3
from ldap3 import Server, Connection, ALL
from cryptography.fernet import Fernet

# ==============================================================================
# Configuração Base
# ==============================================================================
basedir = os.path.abspath(os.path.dirname(__file__))
logs_dir = os.path.join(basedir, 'logs')
os.makedirs(logs_dir, exist_ok=True)

log_path = os.path.join(logs_dir, 'schedule_manager.log') # Nome do log atualizado
logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

data_dir = os.path.join(basedir, 'data') # Define o diretório de dados
CONFIG_FILE = os.path.join(data_dir, 'config.json')
KEY_FILE = os.path.join(data_dir, 'secret.key')
SCHEDULE_FILE = os.path.join(data_dir, 'schedules.json')
DISABLE_SCHEDULE_FILE = os.path.join(data_dir, 'disable_schedules.json')
GROUP_SCHEDULE_FILE = os.path.join(data_dir, 'group_schedules.json')

# ==============================================================================
# Funções de Criptografia e Configuração
# ==============================================================================
def load_key():
    """Carrega a chave de 'secret.key' ou a cria se não existir."""
    if not os.path.exists(KEY_FILE):
        logging.warning("Arquivo de chave 'secret.key' não encontrado. Gerando um novo.")
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key
    return open(KEY_FILE, "rb").read()

def load_config():
    """Carrega a configuração de 'config.json' ou cria um arquivo vazio."""
    if not os.path.exists(CONFIG_FILE):
        logging.warning("Arquivo 'config.json' não encontrado. Criando um arquivo de configuração vazio.")
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump({}, f)
        return {}
    try:
        key = load_key()
        cipher_suite = Fernet(key)
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            encrypted_config = json.load(f)
        config = {}
        SENSITIVE_KEYS = ['DEFAULT_PASSWORD', 'SERVICE_ACCOUNT_PASSWORD']
        for k, v in encrypted_config.items():
            if k in SENSITIVE_KEYS and v:
                try:
                    config[k] = cipher_suite.decrypt(v.encode()).decode()
                except Exception:
                    config[k] = v
            else:
                config[k] = v
        return config
    except Exception as e:
        logging.error(f"Erro ao carregar configuração: {e}")
        return {}

# ==============================================================================
# Funções de Conexão e Lógica AD
# ==============================================================================
def get_ldap_connection(config):
    if not all(k in config for k in ['AD_SERVER', 'SERVICE_ACCOUNT_USER', 'SERVICE_ACCOUNT_PASSWORD']):
        logging.error("Configuração do AD incompleta.")
        return None
    try:
        server = Server(config['AD_SERVER'], use_ssl=config.get('USE_LDAPS', False), get_info=ALL)
        conn = Connection(server, user=config['SERVICE_ACCOUNT_USER'], password=config['SERVICE_ACCOUNT_PASSWORD'], auto_bind=True)
        return conn
    except Exception as e:
        logging.error(f"Falha ao conectar ao AD: {e}")
        return None

def get_user_by_samaccountname(conn, sam_account_name, search_base):
    conn.search(search_base, f'(sAMAccountName={sam_account_name})', attributes=['distinguishedName', 'userAccountControl'])
    return conn.entries[0] if conn.entries else None

def get_group_by_name(conn, group_name, search_base):
    conn.search(search_base, f'(&(objectClass=group)(cn={group_name}))', attributes=['distinguishedName'])
    return conn.entries[0] if conn.entries else None

# ==============================================================================
# Lógica Principal do Script
# ==============================================================================
def process_user_deactivations(conn, search_base):
    """Processa a desativação agendada de contas de usuário."""
    logging.info("Iniciando verificação de desativações de usuários.")
    try:
        with open(DISABLE_SCHEDULE_FILE, 'r') as f:
            schedules = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logging.info("Nenhum arquivo de agendamento de desativação ('disable_schedules.json') encontrado.")
        return

    today = date.today().isoformat()
    schedules_to_keep = {}
    for username, deactivation_date in schedules.items():
        if deactivation_date <= today:
            logging.info(f"Tentando desativar o usuário '{username}' agendado para {deactivation_date}.")
            user = get_user_by_samaccountname(conn, username, search_base)
            if user:
                uac = user.userAccountControl.value
                if not (uac & 2): # Se a conta NÃO estiver desativada
                    new_uac = uac | 2 # Adiciona a flag de desativação
                    conn.modify(user.distinguishedName.value, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [str(new_uac)])]})
                    if conn.result['description'] == 'success':
                        logging.info(f"Usuário '{username}' desativado com sucesso.")
                    else:
                        logging.error(f"Falha ao desativar '{username}': {conn.result['message']}. Mantendo agendamento.")
                        schedules_to_keep[username] = deactivation_date
                else:
                    logging.warning(f"Usuário '{username}' já estava desativado. Removendo agendamento de desativação.")
            else:
                logging.warning(f"Usuário '{username}' agendado para desativação não encontrado. Removendo agendamento.")
        else:
            schedules_to_keep[username] = deactivation_date

    with open(DISABLE_SCHEDULE_FILE, 'w') as f:
        json.dump(schedules_to_keep, f, indent=4)
    logging.info("Verificação de desativações de usuários concluída.")


def process_user_reactivations(conn, search_base):
    """Processa a reativação de contas de usuário."""
    logging.info("Iniciando verificação de reativações de usuários.")
    try:
        with open(SCHEDULE_FILE, 'r') as f:
            schedules = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logging.info("Nenhum arquivo de agendamento de reativação ('schedules.json') encontrado.")
        return

    today = date.today().isoformat()
    schedules_to_keep = {}
    for username, reactivation_date in schedules.items():
        if reactivation_date <= today:
            logging.info(f"Tentando reativar o usuário '{username}' agendado para {reactivation_date}.")
            user = get_user_by_samaccountname(conn, username, search_base)
            if user:
                uac = user.userAccountControl.value
                if uac & 2:  # Se a conta estiver desativada
                    new_uac = uac - 2
                    conn.modify(user.distinguishedName.value, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [str(new_uac)])]})
                    if conn.result['description'] == 'success':
                        logging.info(f"Usuário '{username}' reativado com sucesso.")
                    else:
                        logging.error(f"Falha ao reativar '{username}': {conn.result['message']}. Mantendo agendamento.")
                        schedules_to_keep[username] = reactivation_date
                else:
                    logging.warning(f"Usuário '{username}' já estava ativo. Removendo agendamento de reativação.")
            else:
                logging.warning(f"Usuário '{username}' agendado para reativação não encontrado. Removendo agendamento.")
        else:
            schedules_to_keep[username] = reactivation_date

    with open(SCHEDULE_FILE, 'w') as f:
        json.dump(schedules_to_keep, f, indent=4)
    logging.info("Verificação de reativações de usuários concluída.")

def process_group_membership_changes(conn, search_base):
    """Processa as alterações agendadas de associação a grupos."""
    logging.info("Iniciando verificação de alterações de associação a grupos.")
    try:
        with open(GROUP_SCHEDULE_FILE, 'r') as f:
            schedules = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logging.info("Nenhum arquivo de agendamento de grupos ('group_schedules.json') encontrado.")
        return

    today = date.today().isoformat()
    remaining_schedules = []
    for schedule in schedules:
        if schedule.get('revert_date') <= today:
            user_sam, group_name, action = schedule['user_sam'], schedule['group_name'], schedule['revert_action']
            logging.info(f"Processando: {action} '{user_sam}' em '{group_name}'.")
            user = get_user_by_samaccountname(conn, user_sam, search_base)
            group = get_group_by_name(conn, group_name, search_base)
            if not user or not group:
                logging.warning(f"Usuário '{user_sam}' ou grupo '{group_name}' não encontrado. Removendo agendamento.")
                continue
            try:
                if action == 'add':
                    conn.extend.microsoft.add_members_to_groups([user.distinguishedName.value], group.distinguishedName.value)
                elif action == 'remove':
                    conn.extend.microsoft.remove_members_from_groups([user.distinguishedName.value], group.distinguishedName.value)
                if conn.result['description'] == 'success':
                    logging.info(f"Sucesso na ação '{action}'.")
                else:
                    logging.error(f"Falha na ação '{action}': {conn.result['message']}. Mantendo agendamento.")
                    remaining_schedules.append(schedule)
            except Exception as e:
                logging.error(f"Exceção ao processar agendamento para '{user_sam}': {e}. Mantendo agendamento.")
                remaining_schedules.append(schedule)
        else:
            remaining_schedules.append(schedule)

    with open(GROUP_SCHEDULE_FILE, 'w') as f:
        json.dump(remaining_schedules, f, indent=4)
    logging.info("Verificação de alterações de associação a grupos concluída.")


if __name__ == "__main__":
    logging.info("=============================================")
    logging.info("Iniciando Gerenciador de Agendamentos do AD.")
    config = load_config()
    conn = get_ldap_connection(config)

    if conn:
        search_base = config.get('AD_SEARCH_BASE')
        if search_base:
            try:
                process_user_deactivations(conn, search_base)
                process_user_reactivations(conn, search_base)
                process_group_membership_changes(conn, search_base)
            except Exception as e:
                logging.critical(f"Erro inesperado durante o processamento de agendamentos: {e}", exc_info=True)
            finally:
                conn.unbind()
                logging.info("Conexão com o AD encerrada.")
        else:
            logging.error("AD_SEARCH_BASE não definido. As operações de AD foram puladas.")
    else:
        logging.error("Não foi possível conectar ao AD. As operações de AD foram puladas.")
        logging.info("Conexão com o AD encerrada.")
        logging.info("Gerenciador de Agendamentos do AD finalizado.")
        logging.info("=============================================\n")