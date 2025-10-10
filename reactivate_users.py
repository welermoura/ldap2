#!/usr/bin/env python3
import os
import json
from datetime import date
import logging
import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE
from cryptography.fernet import Fernet

# ==============================================================================
# Configuração Base
# ==============================================================================
basedir = os.path.abspath(os.path.dirname(__file__))
logs_dir = os.path.join(basedir, 'logs')
os.makedirs(logs_dir, exist_ok=True)

# Configuração do Logging
log_path = os.path.join(logs_dir, 'reactivator.log')
logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

# Caminhos dos arquivos
CONFIG_FILE = os.path.join(basedir, 'config.json')
KEY_FILE = os.path.join(basedir, 'secret.key')
SCHEDULE_FILE = os.path.join(basedir, 'schedules.json')
GROUP_SCHEDULE_FILE = os.path.join(basedir, 'group_schedules.json')

# ==============================================================================
# Funções de Criptografia e Configuração (copiadas de app.py)
# ==============================================================================
def load_key():
    """Carrega a chave de 'secret.key'."""
    try:
        return open(KEY_FILE, "rb").read()
    except FileNotFoundError:
        logging.error("Arquivo de chave 'secret.key' não encontrado. O script não pode descriptografar a configuração.")
        raise

def load_config():
    """Carrega, descriptografa e retorna os dados de configuração."""
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
                except Exception as e:
                    logging.error(f"Falha ao descriptografar a chave '{k}'. Erro: {e}")
                    # Pode ser um valor antigo não criptografado, mas logamos o erro.
                    config[k] = v
            else:
                config[k] = v
        return config
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Erro ao carregar o arquivo de configuração: {e}")
        return {}

# ==============================================================================
# Funções de Conexão e Lógica AD
# ==============================================================================
def get_ldap_connection(config):
    """Cria e retorna uma conexão LDAP."""
    ad_server = config.get('AD_SERVER')
    use_ldaps = config.get('USE_LDAPS', False)
    user = config.get('SERVICE_ACCOUNT_USER')
    password = config.get('SERVICE_ACCOUNT_PASSWORD')

    if not all([ad_server, user, password]):
        logging.error("Configuração do servidor AD ou da conta de serviço está incompleta.")
        return None

    try:
        server = Server(ad_server, use_ssl=use_ldaps, get_info=ALL)
        conn = Connection(server, user=user, password=password, auto_bind=True)
        logging.info(f"Conexão com o servidor AD '{ad_server}' estabelecida com sucesso.")
        return conn
    except Exception as e:
        logging.error(f"Falha ao conectar ao servidor AD '{ad_server}': {e}")
        return None

def get_user_by_samaccountname(conn, sam_account_name, search_base):
    """Busca um usuário pelo sAMAccountName."""
    conn.search(search_base, f'(sAMAccountName={sam_account_name})', attributes=['distinguishedName', 'userAccountControl'])
    return conn.entries[0] if conn.entries else None

def get_group_by_name(conn, group_name, search_base):
    """Busca um grupo pelo nome (cn)."""
    conn.search(search_base, f'(&(objectClass=group)(cn={group_name}))', attributes=['distinguishedName'])
    return conn.entries[0] if conn.entries else None

# ==============================================================================
# Lógica Principal do Script
# ==============================================================================
def process_user_reactivations(conn, search_base):
    """Processa a reativação de contas de usuário de forma robusta."""
    logging.info("Iniciando verificação de reativações de usuários.")
    try:
        with open(SCHEDULE_FILE, 'r') as f:
            schedules = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logging.info("Nenhum arquivo de agendamento de usuários ('schedules.json') encontrado ou está vazio. Pulando.")
        return

    today = date.today().isoformat()
    schedules_to_keep = {}

    for username, reactivation_date in schedules.items():
        if reactivation_date <= today:
            logging.info(f"Tentando reativar o usuário '{username}' agendado para {reactivation_date}.")
            user = get_user_by_samaccountname(conn, username, search_base)
            if user:
                uac = user.userAccountControl.value
                if uac & 2:  # Se a conta estiver desativada (flag 2)
                    new_uac = uac - 2
                    conn.modify(user.distinguishedName.value, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [str(new_uac)])]})
                    if conn.result['description'] == 'success':
                        logging.info(f"Usuário '{username}' reativado com sucesso. Agendamento removido.")
                    else:
                        logging.error(f"Falha ao reativar '{username}': {conn.result['message']}. Mantendo agendamento para próxima execução.")
                        schedules_to_keep[username] = reactivation_date  # Mantém o agendamento se a reativação falhar
                else:
                    logging.warning(f"Usuário '{username}' já estava ativo. Removendo agendamento.")
            else:
                logging.warning(f"Usuário '{username}' agendado para reativação não foi encontrado no AD. Removendo agendamento.")
        else:
            # A data de reativação é no futuro, então mantém o agendamento.
            schedules_to_keep[username] = reactivation_date

    with open(SCHEDULE_FILE, 'w') as f:
        json.dump(schedules_to_keep, f, indent=4)
    logging.info("Verificação de reativações de usuários concluída.")

def process_group_membership_changes(conn, search_base):
    """Processa as alterações agendadas de associação a grupos de forma robusta."""
    logging.info("Iniciando verificação de alterações de associação a grupos.")
    try:
        with open(GROUP_SCHEDULE_FILE, 'r') as f:
            schedules = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logging.info("Nenhum arquivo de agendamento de grupos ('group_schedules.json') encontrado ou está vazio. Pulando.")
        return

    today = date.today().isoformat()
    remaining_schedules = []

    for schedule in schedules:
        if schedule['revert_date'] <= today:
            user_sam = schedule['user_sam']
            group_name = schedule['group_name']
            action = schedule['revert_action']

            logging.info(f"Processando agendamento para '{user_sam}' no grupo '{group_name}'. Ação: {action}.")

            user = get_user_by_samaccountname(conn, user_sam, search_base)
            group = get_group_by_name(conn, group_name, search_base)

            if not user or not group:
                logging.warning(f"Usuário '{user_sam}' ou grupo '{group_name}' não encontrado. Removendo agendamento inválido.")
                continue

            try:
                if action == 'add':
                    conn.extend.microsoft.add_members_to_groups([user.distinguishedName.value], group.distinguishedName.value)
                elif action == 'remove':
                    conn.extend.microsoft.remove_members_from_groups([user.distinguishedName.value], group.distinguishedName.value)
                else:
                    logging.warning(f"Ação desconhecida '{action}' para o agendamento. Ignorando.")
                    continue

                if conn.result['description'] == 'success':
                    logging.info(f"Sucesso: Usuário '{user_sam}' foi '{'adicionado a' if action == 'add' else 'removido de'}' '{group_name}'. Agendamento concluído.")
                else:
                    logging.error(f"Falha ao executar ação '{action}' para '{user_sam}' em '{group_name}': {conn.result['message']}. Mantendo agendamento.")
                    remaining_schedules.append(schedule)
            except Exception as e:
                logging.error(f"Erro de exceção ao processar agendamento para '{user_sam}' em '{group_name}': {e}. Mantendo agendamento.")
                remaining_schedules.append(schedule)
        else:
            remaining_schedules.append(schedule)

    with open(GROUP_SCHEDULE_FILE, 'w') as f:
        json.dump(remaining_schedules, f, indent=4)
    logging.info("Verificação de alterações de associação a grupos concluída.")


if __name__ == "__main__":
    logging.info("=============================================")
    logging.info("Iniciando script de tarefas agendadas do AD.")

    config = load_config()
    if not config:
        logging.critical("Configuração não carregada. Abortando.")
        exit(1)

    conn = get_ldap_connection(config)
    if not conn:
        logging.critical("Não foi possível estabelecer conexão com o AD. Abortando.")
        exit(1)

    search_base = config.get('AD_SEARCH_BASE')
    if not search_base:
        logging.critical("AD_SEARCH_BASE não definido na configuração. Abortando.")
        exit(1)

    try:
        process_user_reactivations(conn, search_base)
        process_group_membership_changes(conn, search_base)
    except Exception as e:
        logging.critical(f"Ocorreu um erro inesperado durante a execução do script: {e}", exc_info=True)
    finally:
        conn.unbind()
        logging.info("Conexão com o AD encerrada.")
        logging.info("Script de tarefas agendadas do AD finalizado.")
        logging.info("=============================================\n")