import os
import logging
from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, ValidationError, Length, EqualTo
import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE, BASE
from ldap3.utils.conv import escape_filter_chars
from datetime import datetime, timedelta, date, timezone
import json
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re
from cryptography.fernet import Fernet
import secrets

# ==============================================================================
# Configuração Base
# ==============================================================================
basedir = os.path.abspath(os.path.dirname(__file__))
logs_dir = os.path.join(basedir, 'logs')
os.makedirs(logs_dir, exist_ok=True)
log_path = os.path.join(logs_dir, 'ad_creator.log')
logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', encoding='utf-8')
app = Flask(__name__)

def get_flask_secret_key():
    """
    Carrega a secret key do Flask de forma segura.
    Prioridade:
    1. Variável de ambiente SECRET_KEY.
    2. Arquivo flask_secret.key no diretório base.
    3. Gera uma nova chave e salva no arquivo se nenhuma das anteriores existir.
    """
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key

    key_file_path = os.path.join(basedir, 'flask_secret.key')

    if os.path.exists(key_file_path):
        with open(key_file_path, 'r') as f:
            return f.read().strip()
    else:
        new_key = secrets.token_hex(32)
        with open(key_file_path, 'w') as f:
            f.write(new_key)
        # Define permissões restritivas para o arquivo da chave
        os.chmod(key_file_path, 0o600)
        return new_key

app.secret_key = get_flask_secret_key()
SCHEDULE_FILE = os.path.join(basedir, 'schedules.json')
PERMISSIONS_FILE = os.path.join(basedir, 'permissions.json')
KEY_FILE = os.path.join(basedir, 'secret.key')
CONFIG_FILE = os.path.join(basedir, 'config.json')


# ==============================================================================
# Funções de Criptografia e Configuração Segura
# ==============================================================================
def write_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

def load_key():
    if not os.path.exists(KEY_FILE):
        write_key()
    return open(KEY_FILE, "rb").read()

key = load_key()
cipher_suite = Fernet(key)
SENSITIVE_KEYS = ['DEFAULT_PASSWORD', 'SERVICE_ACCOUNT_PASSWORD']

def load_config():
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            encrypted_config = json.load(f)
        config = {}
        for k, v in encrypted_config.items():
            if k in SENSITIVE_KEYS and v:
                try:
                    config[k] = cipher_suite.decrypt(v.encode()).decode()
                except Exception:
                    config[k] = v
            else:
                config[k] = v
        return config
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_config(config):
    encrypted_config = {}
    config_copy = config.copy()
    for k, v in config_copy.items():
        if k in SENSITIVE_KEYS and v:
            encrypted_config[k] = cipher_suite.encrypt(v.encode()).decode()
        else:
            encrypted_config[k] = v
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(encrypted_config, f, indent=4)

# ==============================================================================
# Funções Auxiliares de User/Schedule/Permissions
# ==============================================================================
def load_user():
    user_path = os.path.join(basedir, 'user.json')
    try:
        with open(user_path, 'r', encoding='utf-8') as f: return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError): return None

def save_user(user_data):
    user_path = os.path.join(basedir, 'user.json')
    with open(user_path, 'w', encoding='utf-8') as f: json.dump(user_data, f, indent=4)

def load_schedules():
    try:
        with open(SCHEDULE_FILE, 'r', encoding='utf-8') as f: return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError): return {}

def save_schedules(schedules):
    with open(SCHEDULE_FILE, 'w', encoding='utf-8') as f: json.dump(schedules, f, indent=4)

GROUP_SCHEDULE_FILE = os.path.join(basedir, 'group_schedules.json')

def load_group_schedules():
    try:
        with open(GROUP_SCHEDULE_FILE, 'r', encoding='utf-8') as f: return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError): return []

def save_group_schedules(schedules):
    with open(GROUP_SCHEDULE_FILE, 'w', encoding='utf-8') as f: json.dump(schedules, f, indent=4)

def load_permissions():
    try:
        with open(PERMISSIONS_FILE, 'r', encoding='utf-8') as f: return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError): return {}

def save_permissions(permissions):
    with open(PERMISSIONS_FILE, 'w', encoding='utf-8') as f: json.dump(permissions, f, indent=4)

# ==============================================================================
# Lógica de Permissões
# ==============================================================================
def user_has_any_permission(user_groups):
    permissions = load_permissions()
    if not permissions or not user_groups: return False
    for group in user_groups:
        rule = permissions.get(group)
        if rule and rule.get('type') in ['full', 'custom']: return True
    return False

def check_permission(action=None, field=None):
    user_groups = session.get('user_groups', [])
    permissions = load_permissions()
    if not permissions or not user_groups: return False
    for group in user_groups:
        rule = permissions.get(group)
        if not rule: continue
        if rule.get('type') == 'full': return True
        if rule.get('type') == 'custom':
            if action and rule.get('actions', {}).get(action): return True
            if field and field in rule.get('fields', []): return True
    return False

def require_permission(action=None, field=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not check_permission(action=action, field=field):
                flash('Você não tem permissão para realizar esta ação.', 'error')
                return redirect(request.referrer or url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_api_permission(action=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not check_permission(action=action): return jsonify({'error': 'Permissão negada.'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==============================================================================
# Decorators e Processadores de Contexto
# ==============================================================================
@app.before_request
def before_request_func():
    if not load_user() and request.endpoint not in ['admin_register', 'static']:
        return redirect(url_for('admin_register'))

def is_authenticated():
    return 'ad_user' in session

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            flash("Sua sessão expirou. Por favor, faça login novamente.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_year():
    return {'year': datetime.now().year}

@app.context_processor
def inject_user_status_processor():
    return dict(get_user_status=get_user_status)

@app.context_processor
def inject_attr_value_getter():
    return dict(get_attr_value=get_attr_value)

@app.context_processor
def inject_permission_checker():
    return dict(check_permission=check_permission)

def handle_ldap_exceptions(f):
    """
    Decorator para tratar exceções comuns do LDAP de forma centralizada,
    melhorando o feedback ao usuário e a resiliência da aplicação.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
            # Lida com falha de login do usuário (ex: senha alterada)
            if not session.get('sso_login', False):
                session.clear()
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Credenciais inválidas ou sessão expirada.'}), 401
                flash("Suas credenciais são inválidas ou a sessão expirou. Por favor, faça login novamente.", "error")
                return redirect(url_for('login'))
            # Lida com falha da conta de serviço
            else:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Credenciais da conta de serviço inválidas.'}), 500
                flash("ERRO CRÍTICO: As credenciais da conta de serviço são inválidas. Contate o administrador.", "error")
                logging.error("Credenciais da conta de serviço do AD são inválidas.", exc_info=True)
                return redirect(url_for('dashboard'))
        except ldap3.core.exceptions.LDAPCannotConnectResult as e:
            error_message = f"Não foi possível conectar ao servidor AD: {e}"
            if request.path.startswith('/api/'):
                return jsonify({'error': error_message}), 503
            flash(error_message, "error")
            logging.error(error_message, exc_info=True)
            return redirect(url_for('admin_dashboard') if 'master_admin' in session else url_for('login'))
        except Exception as e:
            logging.error(f"Erro inesperado na rota '{request.endpoint}': {e}", exc_info=True)
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Ocorreu um erro interno no servidor.'}), 500
            flash(f"Ocorreu um erro inesperado: {e}", "error")
            return redirect(request.referrer or url_for('dashboard'))
    return decorated_function

# ==============================================================================
# Validadores Customizados e Funções Auxiliares
# ==============================================================================
def validate_sam_account(form, field):
    if not all(c.isalnum() or c in '.-_' for c in field.data):
        raise ValidationError('O login pode conter apenas letras, números e os caracteres ".", "-" e "_".')

def get_attr_value(user, attr):
    return user[attr].value if attr in user and user[attr].value is not None else ''

def filetime_to_datetime(ft):
    EPOCH_AS_FILETIME = 116444736000000000
    HUNDREDS_OF_NANOSECONDS = 10000000
    if ft is None or int(ft) == 0 or int(ft) == 9223372036854775807:
        return None
    return datetime.fromtimestamp((int(ft) - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS, tz=timezone.utc)


# ==============================================================================
# Modelos de Formulário (Forms)
# ==============================================================================
class LoginForm(FlaskForm):
    username = StringField('Nome de Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')
class CreateUserForm(FlaskForm):
    first_name = StringField('Primeiro Nome', validators=[DataRequired()])
    last_name = StringField('Sobrenome', validators=[DataRequired()])
    sam_account = StringField('Login de Usuário (máx 20 caracteres)', validators=[DataRequired(), Length(max=20), validate_sam_account])
    model_name = StringField('Nome do Usuário Modelo', validators=[DataRequired()])
    telephone = StringField('Telefone (opcional)')
    submit = SubmitField('Buscar Modelo')
class AdminRegistrationForm(FlaskForm):
    username = StringField('Nome de Usuário do Admin', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Senha do Admin', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirmar Senha', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrar Admin')
class AdminLoginForm(FlaskForm):
    username = StringField('Nome de Usuário do Admin', validators=[DataRequired()])
    password = PasswordField('Senha do Admin', validators=[DataRequired()])
    submit = SubmitField('Entrar')
class AdminChangePasswordForm(FlaskForm):
    current_password = PasswordField('Senha Atual', validators=[DataRequired()])
    new_password = PasswordField('Nova Senha', validators=[DataRequired(), Length(min=8, message='A senha deve ter pelo menos 8 caracteres.')])
    confirm_new_password = PasswordField('Confirmar Nova Senha', validators=[DataRequired(), EqualTo('new_password', message='As senhas não coincidem.')])
    submit = SubmitField('Alterar Senha')
class ConfigForm(FlaskForm):
    ad_server = StringField('Servidor AD', validators=[DataRequired()])
    use_ldaps = BooleanField('Usar LDAPS (SSL)', default=False)
    ad_domain = StringField('Domínio (NetBIOS name, ex: MEUDOMINIO)', validators=[DataRequired()])
    ad_search_base = StringField('Base de Busca AD (ex: OU=Usuarios,DC=dominio,DC=com)', validators=[DataRequired()])
    sso_enabled = BooleanField('Habilitar Single Sign-On (SSO)', default=False)
    default_password = PasswordField('Senha Padrão (deixe em branco para não alterar)')
    service_account_user = StringField('Usuário de Serviço (para tarefas automáticas)')
    service_account_password = PasswordField('Senha do Usuário de Serviço (deixe em branco para não alterar)')
    submit = SubmitField('Salvar Configuração')
class UserSearchForm(FlaskForm):
    search_query = StringField('Buscar Usuário (Nome ou Login)', validators=[DataRequired()])
    submit = SubmitField('Buscar')
class GroupSearchForm(FlaskForm):
    search_query = StringField('Buscar Grupo por Nome', validators=[DataRequired()])
    submit = SubmitField('Buscar')
class LogSearchForm(FlaskForm):
    search_query = StringField('Filtrar Log por Texto')
    submit = SubmitField('Filtrar')
class EditUserForm(FlaskForm):
    first_name = StringField('Nome', validators=[DataRequired()])
    initials = StringField('Iniciais')
    last_name = StringField('Sobrenome', validators=[DataRequired()])
    display_name = StringField('Nome de Exibição', validators=[DataRequired()])
    description = StringField('Descrição')
    office = StringField('Escritório')
    telephone = StringField('Telefone Principal')
    email = StringField('E-mail')
    web_page = StringField('Página da Web')
    street = StringField('Rua')
    post_office_box = StringField('Caixa Postal')
    city = StringField('Cidade')
    state = StringField('Estado/Província')
    zip_code = StringField('CEP')
    home_phone = StringField('Telefone Residencial')
    pager = StringField('Pager')
    mobile = StringField('Celular')
    fax = StringField('Fax')
    title = StringField('Cargo')
    department = StringField('Departamento')
    company = StringField('Empresa')
    submit = SubmitField('Salvar Alterações')


# ==============================================================================
# Funções Auxiliares do Active Directory
# ==============================================================================
def get_ldap_connection(user, password):
    config = load_config()
    server = Server(config.get('AD_SERVER'), use_ssl=config.get('USE_LDAPS', False), get_info=ALL)
    return Connection(server, user=user, password=password, auto_bind=True)

def get_service_account_connection():
    config = load_config()
    user, password = config.get('SERVICE_ACCOUNT_USER'), config.get('SERVICE_ACCOUNT_PASSWORD')
    if not user or not password: raise Exception("Conta de serviço não configurada.")
    return get_ldap_connection(user, password)

def get_user_connection():
    user, password = session.get('ad_user'), session.get('ad_password')
    if not user or not password: raise Exception("Credenciais do usuário não estão na sessão.")
    return get_ldap_connection(user, password)

def get_read_connection():
    if session.get('sso_login', False):
        try: return get_service_account_connection()
        except Exception as e: raise Exception(f"Login SSO requer conta de serviço. Erro: {e}")
    else:
        return get_user_connection()

def get_user_by_samaccountname(conn, sam_account_name, attributes=None):
    if attributes is None: attributes = ldap3.ALL_ATTRIBUTES
    config = load_config()
    search_base = config.get('AD_SEARCH_BASE', conn.server.info.other['defaultNamingContext'][0])
    safe_sam = escape_filter_chars(sam_account_name)
    conn.search(search_base, f'(sAMAccountName={safe_sam})', attributes=attributes)
    return conn.entries[0] if conn.entries else None

def get_group_by_name(conn, group_name, attributes=None):
    if attributes is None: attributes = ldap3.ALL_ATTRIBUTES
    config = load_config()
    search_base = config.get('AD_SEARCH_BASE', conn.server.info.other['defaultNamingContext'][0])
    safe_group_name = escape_filter_chars(group_name)
    conn.search(search_base, f'(&(objectClass=group)(cn={safe_group_name}))', attributes=attributes)
    return conn.entries[0] if conn.entries else None

def get_user_by_dn(conn, user_dn, attributes=None):
    if attributes is None: attributes = ldap3.ALL_ATTRIBUTES
    try:
        conn.search(user_dn, '(objectClass=*)', BASE, attributes=attributes)
        if conn.entries: return conn.entries[0]
    except ldap3.core.exceptions.LDAPNoSuchObjectResult: return None
    return None

def get_ou_from_dn(dn):
    return ','.join(dn.split(',')[1:])

def get_ou_path(dn):
    parts = dn.split(',')
    ou_parts = [p.split('=')[1] for p in parts if p.startswith(('OU=', 'CN='))]
    ou_parts.reverse()
    if ou_parts: ou_parts.pop(0)
    return ' --- '.join(ou_parts) if ou_parts else 'N/A'

def get_user_status(user_entry):
    if not user_entry or 'userAccountControl' not in user_entry: return "Desconhecido"
    uac = user_entry.userAccountControl.value
    return "Desativado" if uac & 2 else "Ativo"

def search_general_users(conn, query):
    try:
        config = load_config()
        search_base = config.get('AD_SEARCH_BASE', conn.server.info.other['defaultNamingContext'][0])
        safe_query = escape_filter_chars(query)
        search_filter = f"(&(objectClass=user)(objectCategory=person)(|(displayName=*{safe_query}*)(sAMAccountName=*{safe_query}*)))"
        attributes_to_get = ['displayName', 'name', 'mail', 'sAMAccountName', 'title', 'l', 'userAccountControl', 'distinguishedName']
        conn.search(search_base, search_filter, SUBTREE, attributes=attributes_to_get, paged_size=100)
        return conn.entries
    except Exception as e:
        logging.error(f"Erro ao buscar usuários com a query '{query}': {str(e)}")
        return []

def get_upn_suffix_from_base(search_base):
    dc_parts = [part.split('=')[1] for part in search_base.split(',') if part.strip().upper().startswith('DC=')]
    if not dc_parts: return None
    return '@' + '.'.join(dc_parts)

def create_ad_user(conn, new_user_data, model_user):
    config = load_config()
    default_password = config.get('DEFAULT_PASSWORD')
    if not default_password:
        return {'success': False, 'message': 'A senha padrão para novos usuários não está configurada no painel de administração.'}

    new_user_dn = None # Inicializa para o bloco de exceção
    try:
        # 1. Determinar OU e DN do novo usuário
        model_ou = get_ou_from_dn(model_user.entry_dn)
        first_name = new_user_data['first_name']
        last_name = new_user_data['last_name']
        full_name = f"{first_name} {last_name}"
        new_user_dn = f"CN={full_name},{model_ou}"

        # 2. Determinar UPN Suffix
        model_upn = get_attr_value(model_user, 'userPrincipalName')
        upn_suffix = ''
        if '@' in model_upn:
            upn_suffix = '@' + model_upn.split('@', 1)[1]
        else:
            base_suffix = get_upn_suffix_from_base(config.get('AD_SEARCH_BASE'))
            if not base_suffix:
                return {'success': False, 'message': 'Não foi possível determinar o sufixo UPN para o novo usuário.'}
            upn_suffix = base_suffix

        # 3. Montar atributos do novo usuário
        sam_account = new_user_data['sam_account']
        attributes = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'cn': full_name,
            'givenName': first_name,
            'sn': last_name,
            'displayName': full_name,
            'sAMAccountName': sam_account,
            'userPrincipalName': f"{sam_account}{upn_suffix}",
            'telephoneNumber': new_user_data.get('telephone', ''),
            'company': get_attr_value(model_user, 'company'),
            'department': get_attr_value(model_user, 'department'),
            'physicalDeliveryOfficeName': get_attr_value(model_user, 'physicalDeliveryOfficeName'),
        }

        # 4. Criar o usuário (inicialmente desabilitado por padrão)
        conn.add(new_user_dn, attributes=attributes)
        if conn.result['result'] != 0:
            raise Exception(f"Falha ao adicionar usuário ao AD: {conn.result['description']} - {conn.result.get('message', '')}")

        # 5. Definir a senha e habilitar a conta
        conn.extend.microsoft.modify_password(new_user_dn, default_password)
        if conn.result['description'] != 'success':
            raise Exception(f"Falha ao definir a senha: {conn.result['message']}")

        conn.modify(new_user_dn, {'pwdLastSet': [(ldap3.MODIFY_REPLACE, [0])]}) # Forçar troca no primeiro login
        conn.modify(new_user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [str(512)])]}) # Habilitar conta
        if conn.result['result'] != 0:
            raise Exception(f"Falha ao habilitar a conta: {conn.result['description']}")

        # 6. Adicionar usuário aos grupos do modelo
        model_groups = get_attr_value(model_user, 'memberOf')
        if model_groups:
            group_dns = model_groups if isinstance(model_groups, list) else [model_groups]
            for group_dn in group_dns:
                try:
                    conn.extend.microsoft.add_members_to_groups([new_user_dn], group_dn)
                except Exception as group_error:
                    logging.warning(f"Não foi possível adicionar o usuário '{sam_account}' ao grupo '{group_dn}': {group_error}")

        logging.info(f"Usuário '{sam_account}' criado com sucesso por '{session.get('ad_user')}' usando o modelo '{get_attr_value(model_user, 'sAMAccountName')}'.")
        return {'success': True, 'displayName': full_name, 'samAccountName': sam_account, 'password': default_password}

    except ldap3.core.exceptions.LDAPEntryAlreadyExistsResult:
        return {'success': False, 'message': f"O usuário '{full_name}' (DN: {new_user_dn}) já existe no Active Directory."}
    except Exception as e:
        logging.error(f"Erro ao criar usuário '{new_user_data.get('sam_account')}': {str(e)}", exc_info=True)
        if new_user_dn:
            try:
                conn.delete(new_user_dn)
                logging.info(f"Usuário parcialmente criado '{new_user_dn}' foi removido após erro.")
            except Exception:
                pass
        return {'success': False, 'message': f"Ocorreu um erro inesperado: {str(e)}"}

# ==============================================================================
# Funções do Dashboard
# ==============================================================================
def get_dashboard_stats(conn):
    stats = {'enabled_users': 0, 'disabled_users': 0}
    config = load_config()
    search_base = config.get('AD_SEARCH_BASE')
    if not search_base: return stats

    try:
        user_filter = '(&(objectClass=user)(objectCategory=person))'
        entry_generator = conn.extend.standard.paged_search(
            search_base=search_base,
            search_filter=user_filter,
            attributes=['userAccountControl'],
            paged_size=500
        )

        user_count = 0
        for entry in entry_generator:
            user_count += 1
            attributes = entry.get('attributes', {})
            uac = attributes.get('userAccountControl')
            if uac and (int(uac) & 2):
                stats['disabled_users'] += 1
            else:
                stats['enabled_users'] += 1
        logging.info(f"Dashboard: contagem de usuários ativos/desativados processou {user_count} entradas.")

    except Exception as e:
        logging.error(f"Erro ao buscar estatísticas do dashboard: {e}", exc_info=True)

    return stats

def get_locked_accounts(conn):
    config = load_config()
    search_base = config.get('AD_SEARCH_BASE')
    if not search_base: return 0
    try:
        conn.search(search_base, "(&(objectClass=user)(objectCategory=person)(lockoutTime>=1))", attributes=['cn'])
        return len(conn.entries)
    except Exception as e:
        logging.error(f"Erro ao buscar contas bloqueadas: {e}")
        return 0

def get_accounts_locked_in_last_week(conn):
    config = load_config()
    search_base = config.get('AD_SEARCH_BASE')
    if not search_base: return 0
    try:
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        epoch_start = datetime(1601, 1, 1, tzinfo=timezone.utc)
        delta = seven_days_ago - epoch_start
        filetime_timestamp = int(delta.total_seconds() * 10_000_000)

        search_filter = f"(&(objectClass=user)(objectCategory=person)(lockoutTime>={filetime_timestamp}))"
        conn.search(search_base, search_filter, attributes=['cn'], paged_size=1000)
        return len(conn.entries)
    except Exception as e:
        logging.error(f"Erro ao buscar contas bloqueadas na última semana: {e}", exc_info=True)
        return 0

def get_pending_reactivations(days=7):
    schedules = load_schedules()
    count = 0
    today = date.today()
    limit_date = today + timedelta(days=days)
    for username, date_str in schedules.items():
        try:
            reactivation_date = date.fromisoformat(date_str)
            if today <= reactivation_date < limit_date:
                count += 1
        except (ValueError, TypeError):
            continue
    return count

def get_expiring_passwords(conn, days=15):
    expiring_users = []
    config = load_config()
    search_base = config.get('AD_SEARCH_BASE')
    if not search_base: return expiring_users
    try:
        search_filter = "(&(objectClass=user)(objectCategory=person)(!(&(userAccountControl:1.2.840.113556.1.4.803:=2)(userAccountControl:1.2.840.113556.1.4.803:=65536))))"
        attributes = ['cn', 'sAMAccountName', 'msDS-UserPasswordExpiryTimeComputed']

        entry_generator = conn.extend.standard.paged_search(search_base, search_filter, attributes=attributes, paged_size=1000)

        now_utc = datetime.now(timezone.utc)
        expiration_limit = now_utc + timedelta(days=days)

        for entry in entry_generator:
            attributes = entry.get('attributes', {})
            expiry_time_ft = attributes.get('msDS-UserPasswordExpiryTimeComputed')
            if expiry_time_ft:
                expiry_datetime = filetime_to_datetime(expiry_time_ft)
                if expiry_datetime and now_utc < expiry_datetime < expiration_limit:
                    delta = expiry_datetime - now_utc
                    expiring_users.append({'cn': attributes.get('cn'), 'sam': attributes.get('sAMAccountName'), 'expires_in_days': delta.days + 1})
    except Exception as e:
        logging.error(f"Erro ao buscar senhas expirando: {e}", exc_info=True)
        return []

    return sorted(expiring_users, key=lambda x: x['expires_in_days'])

# ==============================================================================
# Rotas Principais da Aplicação
# ==============================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    config = load_config()
    sso_enabled = config.get('SSO_ENABLED', False)
    form = LoginForm()
    if form.validate_on_submit():
        try:
            ad_domain = config.get('AD_DOMAIN')
            if not ad_domain:
                flash('O domínio AD não está configurado.', 'error')
                return render_template('login.html', form=form, sso_enabled=sso_enabled)
            username, password = form.username.data, form.password.data
            full_username = f'{ad_domain}\\{username}'
            conn = get_ldap_connection(full_username, password)
            user_object = get_user_by_samaccountname(conn, username, attributes=['memberOf'])
            if not user_object:
                flash('Nome de usuário ou senha inválidos.', 'error')
                return redirect(url_for('login'))
            user_groups = [g.split(',')[0].split('=')[1] for g in user_object.memberOf.values] if 'memberOf' in user_object and user_object.memberOf.value else []
            if not user_has_any_permission(user_groups):
                flash('Você não tem permissão para acessar o sistema.', 'error')
                return redirect(url_for('login'))
            session['ad_user'], session['ad_password'] = full_username, password
            session['user_groups'], session['sso_login'] = user_groups, False
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
            flash('Usuário ou senha incorretos.', 'error')
        except Exception as e:
            flash('Erro de conexão com o servidor.', 'error')
            logging.error(f"Erro de login para '{form.username.data}': {e}", exc_info=True)
    return render_template('login.html', form=form, sso_enabled=sso_enabled)

@app.route('/sso_login')
def sso_login():
    config = load_config()
    if not config.get('SSO_ENABLED', False):
        flash("O Single Sign-On não está habilitado.", "error")
        return redirect(url_for('login'))
    remote_user = request.environ.get('REMOTE_USER')
    if not remote_user:
        flash("Não foi possível obter a identidade do usuário para o SSO.", "error")
        logging.error("SSO Login falhou: REMOTE_USER não encontrado.")
        return redirect(url_for('login'))
    username = remote_user.split('@')[0]
    try:
        conn = get_service_account_connection()
        user_object = get_user_by_samaccountname(conn, username, attributes=['memberOf', 'distinguishedName'])
        if not user_object:
            flash(f"Usuário SSO '{username}' não encontrado no AD.", 'error')
            logging.warning(f"Login SSO falhou, usuário '{username}' não encontrado.")
            return redirect(url_for('login'))
        user_groups = [g.split(',')[0].split('=')[1] for g in user_object.memberOf.values] if 'memberOf' in user_object and user_object.memberOf.value else []
        if not user_has_any_permission(user_groups):
            flash('Você não tem permissão para acessar o sistema.', 'error')
            logging.warning(f"Login SSO para '{username}' falhou por falta de permissão.")
            return redirect(url_for('login'))
        session['ad_user'], session['ad_password'] = user_object.distinguishedName.value, None
        session['user_groups'], session['sso_login'] = user_groups, True
        flash('Login via SSO realizado com sucesso!', 'success')
        logging.info(f"Usuário '{username}' logado via SSO.")
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f"Ocorreu um erro durante o SSO: {e}", 'error')
        logging.error(f"Erro de SSO para '{username}': {e}", exc_info=True)
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu do sistema.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@require_auth
def index():
    return redirect(url_for('dashboard'))

# ---> ROTA DO DASHBOARD ATUALIZADA <---
@app.route('/dashboard')
@require_auth
@handle_ldap_exceptions
def dashboard():
    stats = {'enabled_users': 'N/A', 'disabled_users': 'N/A'}
    expiring_passwords = []
    locked_last_week_count = 'N/A'
    pending_reactivation_count = 'N/A'

    conn = get_read_connection()
    stats = get_dashboard_stats(conn)
    stats['locked_accounts'] = get_locked_accounts(conn)

    locked_last_week_count = get_accounts_locked_in_last_week(conn)
    pending_reactivation_count = get_pending_reactivations(days=7)

    # Este try/except é mantido para a mensagem de erro específica.
    try:
        expiring_passwords = get_expiring_passwords(conn, days=15)
    except Exception as e:
        flash("Não foi possível carregar a lista de senhas expirando. O filtro pode ser incompatível.", "warning")
        logging.error(f"Falha ao carregar senhas expirando: {e}", exc_info=True)

    return render_template(
        'dashboard.html',
        stats=stats,
        expiring_passwords=expiring_passwords,
        locked_last_week_count=locked_last_week_count,
        pending_reactivation_count=pending_reactivation_count
    )

@app.route('/api/dashboard_list/<category>')
@require_auth
@handle_ldap_exceptions
def api_dashboard_list(category):
    conn = get_read_connection()
    config = load_config()
    search_base = config.get('AD_SEARCH_BASE')

    filters = {
        'active_users': "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        'disabled_users': "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=2))",
        'locked_users': "(&(objectClass=user)(objectCategory=person)(lockoutTime>=1))",
    }
    if category not in filters:
        return jsonify({'error': 'Categoria inválida'}), 404

    attributes = ['cn', 'sAMAccountName']
    conn.search(search_base, filters[category], attributes=attributes, paged_size=1000)

    results = [{'cn': get_attr_value(e, 'cn'), 'sam': get_attr_value(e, 'sAMAccountName')} for e in conn.entries]

    return jsonify(sorted(results, key=lambda x: x['cn'].lower()))

@app.route('/api/user_groups/<username>')
@require_auth
@handle_ldap_exceptions
def api_get_user_groups(username):
    read_conn = get_read_connection()
    user = get_user_by_samaccountname(read_conn, username, attributes=['memberOf'])
    if not user: return jsonify({"error": "Usuário não encontrado"}), 404
    if 'memberOf' not in user or not user.memberOf.values: return jsonify([])
    group_dns = user.memberOf.values
    service_conn = get_service_account_connection()
    groups_details = []
    for group_dn in group_dns:
        # Ignora grupos individuais que não podem ser lidos, sem falhar a requisição inteira
        try:
            service_conn.search(group_dn, '(objectClass=group)', search_scope=BASE, attributes=['cn', 'description'])
            if service_conn.entries:
                group = service_conn.entries[0]
                groups_details.append({"cn": get_attr_value(group, 'cn'), "description": get_attr_value(group, 'description')})
        except Exception: continue
    return jsonify(sorted(groups_details, key=lambda g: g['cn'].lower()))

@app.route('/create_user_form', methods=['GET', 'POST'])
@require_auth
@require_permission(action='can_create')
@handle_ldap_exceptions
def create_user_form():
    form = CreateUserForm()
    if form.validate_on_submit():
        conn = get_read_connection()
        model_name = form.model_name.data.strip()
        if not model_name:
            flash("O nome do usuário modelo é obrigatório.", 'error')
            return render_template('create_user_form.html', form=form)
        users = search_general_users(conn, model_name)
        if not users:
            flash(f"Nenhum usuário encontrado com o nome '{model_name}'.", 'error')
            return render_template('create_user_form.html', form=form)
        session['form_data'] = {'first_name': form.first_name.data, 'last_name': form.last_name.data, 'sam_account': form.sam_account.data, 'telephone': form.telephone.data}
        session['found_users_sams'] = [u.sAMAccountName.value for u in users]
        return redirect(url_for('select_model'))
    return render_template('create_user_form.html', form=form)

@app.route('/select_model', methods=['GET', 'POST'])
@require_auth
@require_permission(action='can_create')
@handle_ldap_exceptions
def select_model():
    form_data = session.get('form_data')
    if not form_data: return redirect(url_for('index'))
    users = []
    conn = get_read_connection()
    for sam_name in session.get('found_users_sams', []):
        user_entry = get_user_by_samaccountname(conn, sam_name, ['name', 'sAMAccountName', 'distinguishedName', 'physicalDeliveryOfficeName'])
        if user_entry:
            users.append({'name': user_entry.name.value, 'sam_account': user_entry.sAMAccountName.value, 'office': str(user_entry.physicalDeliveryOfficeName.value) if 'physicalDeliveryOfficeName' in user_entry and user_entry.physicalDeliveryOfficeName.value else 'N/A', 'ou_path': get_ou_path(user_entry.entry_dn)})

    form = FlaskForm()
    if request.method == 'POST':
        selected_user_sam = request.form.get('selected_user_sam')
        if not selected_user_sam:
            flash("Por favor, selecione um usuário modelo.", 'error')
            return render_template('select_model.html', users=users, form_data=form_data, form=form)

        service_conn = get_service_account_connection()
        model_attrs = get_user_by_samaccountname(service_conn, selected_user_sam)
        result = create_ad_user(service_conn, form_data, model_attrs)
        if result['success']:
            session.pop('form_data', None)
            session.pop('found_users_sams', None)
            return render_template('result.html', result=result)
        else:
            flash(result['message'], 'error')
            # Renderiza a mesma página para que o usuário possa escolher outro modelo se desejar
            return render_template('select_model.html', users=users, form_data=form_data, form=form)

    return render_template('select_model.html', users=users, form_data=form_data, form=form)

@app.route('/result')
@require_auth
def result(): return redirect(url_for('index'))

@app.route('/manage_users', methods=['GET', 'POST'])
@require_auth
@handle_ldap_exceptions
def manage_users():
    form = UserSearchForm()
    users = []
    if form.validate_on_submit():
        conn = get_read_connection()
        users = search_general_users(conn, form.search_query.data.strip())
    return render_template('manage_users.html', form=form, users=users)

@app.route('/group_management', methods=['GET', 'POST'])
@require_auth
@require_permission(action='can_manage_groups')
@handle_ldap_exceptions
def group_management():
    form = GroupSearchForm()
    groups = []
    if form.validate_on_submit():
        conn = get_service_account_connection()
        config, query = load_config(), form.search_query.data
        search_base = config.get('AD_SEARCH_BASE')
        safe_query = escape_filter_chars(query)
        search_filter = f"(&(objectClass=group)(cn=*{safe_query}*))"
        conn.search(search_base, search_filter, attributes=['cn', 'description', 'member'], paged_size=1000)
        groups = conn.entries
        if not groups: flash(f"Nenhum grupo encontrado com o nome '{query}'.", "info")
    return render_template('manage_groups.html', form=form, groups=groups)

@app.route('/api/group_members/<group_name>')
@require_auth
@require_api_permission(action='can_manage_groups')
@handle_ldap_exceptions
def api_group_members(group_name):
    conn = get_service_account_connection()
    page, per_page, search_query = request.args.get('page', 1, type=int), request.args.get('per_page', 10, type=int), request.args.get('query', '', type=str).strip()
    group = get_group_by_name(conn, group_name, attributes=['member'])
    if not group: return jsonify({'error': 'Group not found'}), 404
    member_dns = group.member.values if group.member.values else []
    if search_query:
        escaped_query = re.escape(search_query)
        member_dns = [dn for dn in member_dns if re.search(f'CN={escaped_query}', dn, re.IGNORECASE)]
    total_members = len(member_dns)
    start, end = (page - 1) * per_page, (page - 1) * per_page + per_page
    paginated_dns, members_details = sorted(member_dns)[start:end], []
    attributes_to_get = ['displayName', 'sAMAccountName', 'title', 'l']
    for dn in paginated_dns:
        user_entry = get_user_by_dn(conn, dn, attributes=attributes_to_get)
        if user_entry: members_details.append({'displayName': get_attr_value(user_entry, 'displayName'), 'sAMAccountName': get_attr_value(user_entry, 'sAMAccountName'), 'title': get_attr_value(user_entry, 'title'), 'city': get_attr_value(user_entry, 'l')})
        else:
            cn_part = dn.split(',')[0]
            display_name = cn_part.split('=')[1] if '=' in cn_part else cn_part
            members_details.append({'displayName': f"{display_name} (Objeto desconhecido)", 'sAMAccountName': 'N/A', 'title': 'N/A', 'city': 'N/A'})
    return jsonify({'members': members_details, 'total': total_members, 'page': page, 'per_page': per_page, 'total_pages': (total_members + per_page - 1) // per_page})

@app.route('/api/search_users_for_group/<group_name>')
@require_auth
@require_api_permission(action='can_manage_groups')
@handle_ldap_exceptions
def api_search_users_for_group(group_name):
    query = request.args.get('query', '')
    if not query or len(query) < 3: return jsonify([])
    conn = get_service_account_connection()
    group = get_group_by_name(conn, group_name, attributes=['member'])
    if not group: return jsonify({'error': 'Group not found'}), 404
    current_member_dns = {m.lower() for m in group.member.values} if group.member.values else set()
    all_found_users = search_general_users(conn, query)
    user_search_results = [{'displayName': get_attr_value(user, 'displayName'), 'sAMAccountName': get_attr_value(user, 'sAMAccountName'), 'title': get_attr_value(user, 'title'), 'city': get_attr_value(user, 'l')} for user in all_found_users if user.distinguishedName.value.lower() not in current_member_dns]
    return jsonify(user_search_results)

@app.route('/view_group/<group_name>')
@require_auth
@require_permission(action='can_manage_groups')
@handle_ldap_exceptions
def view_group(group_name):
    form = FlaskForm()
    conn = get_service_account_connection()
    group = get_group_by_name(conn, group_name, attributes=['cn', 'description'])
    if not group:
        flash(f"Grupo '{group_name}' não encontrado.", 'error')
        return redirect(url_for('group_management'))
    return render_template('view_group.html', group=group, form=form)
@app.route('/add_member/<group_name>', methods=['POST'])
@require_auth
@require_permission(action='can_manage_groups')
@handle_ldap_exceptions
def add_member(group_name):
    user_sam = request.form.get('user_sam')
    if not user_sam:
        flash("Login do usuário não fornecido.", 'error')
        return redirect(url_for('view_group', group_name=group_name))
    conn = get_service_account_connection()
    user_to_add = get_user_by_samaccountname(conn, user_sam, ['distinguishedName'])
    group_to_modify = get_group_by_name(conn, group_name, ['distinguishedName'])
    if user_to_add and group_to_modify:
        conn.extend.microsoft.add_members_to_groups([user_to_add.distinguishedName.value], group_to_modify.distinguishedName.value)
        if conn.result['description'] == 'success':
            flash(f"Usuário '{user_sam}' adicionado ao grupo '{group_name}' com sucesso.", 'success')
            logging.info(f"Usuário '{user_sam}' adicionado ao grupo '{group_name}' por '{session.get('ad_user')}'.")
        else:
            flash(f"Falha ao adicionar usuário: {conn.result['message']}", 'error')
    else: flash("Usuário ou grupo não encontrado.", 'error')
    return redirect(url_for('view_group', group_name=group_name))
@app.route('/remove_member/<group_name>/<user_sam>', methods=['POST'])
@require_auth
@require_permission(action='can_manage_groups')
@handle_ldap_exceptions
def remove_member(group_name, user_sam):
    conn = get_service_account_connection()
    user_to_remove = get_user_by_samaccountname(conn, user_sam, ['distinguishedName'])
    group_to_modify = get_group_by_name(conn, group_name, ['distinguishedName'])
    if user_to_remove and group_to_modify:
        conn.extend.microsoft.remove_members_from_groups([user_to_remove.distinguishedName.value], group_to_modify.distinguishedName.value)
        if conn.result['description'] == 'success':
            flash(f"Usuário '{user_sam}' removido do grupo '{group_name}' com sucesso.", 'success')
            logging.info(f"Usuário '{user_sam}' removido do grupo '{group_name}' por '{session.get('ad_user')}'.")
        else:
            flash(f"Falha ao remover usuário: {conn.result['message']}", 'error')
    else: flash("Usuário ou grupo não encontrado.", 'error')
    return redirect(url_for('view_group', group_name=group_name))
@app.route('/add_member_temp/<group_name>', methods=['POST'])
@require_auth
@require_permission(action='can_manage_groups')
@handle_ldap_exceptions
def add_member_temp(group_name):
    days = int(request.args.get('days'))
    user_sam = request.form.get('user_sam')
    if days <= 0 or not user_sam:
        flash("Informações inválidas para adição temporária.", 'error')
        return redirect(url_for('view_group', group_name=group_name))
    conn = get_service_account_connection()
    user_to_add = get_user_by_samaccountname(conn, user_sam, ['distinguishedName'])
    group_to_modify = get_group_by_name(conn, group_name, ['distinguishedName'])
    if user_to_add and group_to_modify:
        conn.extend.microsoft.add_members_to_groups([user_to_add.distinguishedName.value], group_to_modify.distinguishedName.value)
        if conn.result['description'] == 'success':
            schedules = load_group_schedules()
            revert_date = (date.today() + timedelta(days=days)).isoformat()
            schedules.append({'user_sam': user_sam, 'group_name': group_name, 'revert_action': 'remove', 'revert_date': revert_date})
            save_group_schedules(schedules)
            flash(f"Usuário '{user_sam}' adicionado ao grupo '{group_name}' por {days} dias.", 'success')
            logging.info(f"Usuário '{user_sam}' adicionado temporariamente ao grupo '{group_name}' por '{session.get('ad_user')}'. Reversão em {revert_date}.")
        else: flash(f"Falha ao adicionar usuário: {conn.result['message']}", 'error')
    else: flash("Usuário ou grupo não encontrado.", 'error')
    return redirect(url_for('view_group', group_name=group_name))
@app.route('/remove_member_temp/<group_name>/<user_sam>', methods=['POST'])
@require_auth
@require_permission(action='can_manage_groups')
@handle_ldap_exceptions
def remove_member_temp(group_name, user_sam):
    days = int(request.args.get('days'))
    if days <= 0:
        flash("O número de dias deve ser positivo.", 'error')
        return redirect(url_for('view_group', group_name=group_name))
    conn = get_service_account_connection()
    user_to_remove = get_user_by_samaccountname(conn, user_sam, ['distinguishedName'])
    group_to_modify = get_group_by_name(conn, group_name, ['distinguishedName'])
    if user_to_remove and group_to_modify:
        conn.extend.microsoft.remove_members_from_groups([user_to_remove.distinguishedName.value], group_to_modify.distinguishedName.value)
        if conn.result['description'] == 'success':
            schedules = load_group_schedules()
            revert_date = (date.today() + timedelta(days=days)).isoformat()
            schedules.append({'user_sam': user_sam, 'group_name': group_name, 'revert_action': 'add', 'revert_date': revert_date})
            save_group_schedules(schedules)
            flash(f"Usuário '{user_sam}' removido do grupo '{group_name}' por {days} dias.", 'success')
            logging.info(f"Usuário '{user_sam}' removido temporariamente do grupo '{group_name}' por '{session.get('ad_user')}'. Reversão em {revert_date}.")
        else: flash(f"Falha ao remover usuário: {conn.result['message']}", 'error')
    else: flash("Usuário ou grupo não encontrado.", 'error')
    return redirect(url_for('view_group', group_name=group_name))
@app.route('/view_user/<username>')
@require_auth
@handle_ldap_exceptions
def view_user(username):
    conn = get_read_connection()
    user = get_user_by_samaccountname(conn, username, attributes=['*', 'msDS-UserPasswordExpiryTimeComputed'])
    if not user:
        logging.warning(f"Usuário '{session.get('ad_user')}' tentou ver '{username}' sem sucesso.")
        flash("Usuário não encontrado ou você não tem permissão para ver os detalhes.", "error")
        return redirect(url_for('manage_users'))
    password_expiry_info = "Não aplicável ou senha nunca expira."
    if 'msDS-UserPasswordExpiryTimeComputed' in user and user['msDS-UserPasswordExpiryTimeComputed'].value:
        expiry_time_ft = user['msDS-UserPasswordExpiryTimeComputed'].value
        expiry_datetime = filetime_to_datetime(expiry_time_ft)
        if expiry_datetime:
            delta = expiry_datetime - datetime.now(timezone.utc)
            if delta.days >= 0:
                password_expiry_info = f"Expira em {delta.days} dia(s) ({expiry_datetime.strftime('%d/%m/%Y')})"
            else:
                password_expiry_info = f"Expirou há {-delta.days} dia(s) ({expiry_datetime.strftime('%d/%m/%Y')})"
    form = EditUserForm()
    return render_template('view_user.html', user=user, form=form, password_expiry_info=password_expiry_info)
@app.route('/toggle_status/<username>', methods=['POST'])
@require_auth
@require_permission(action='can_disable')
@handle_ldap_exceptions
def toggle_status(username):
    conn = get_service_account_connection()
    user = get_user_by_samaccountname(conn, username, ['userAccountControl', 'distinguishedName'])
    if not user:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for('manage_users'))
    uac = user.userAccountControl.value
    new_uac, action_message = (uac - 2, "ativada") if uac & 2 else (uac + 2, "desativada")
    conn.modify(user.distinguishedName.value, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [str(new_uac)])]})
    if action_message == "ativada":
        schedules = load_schedules()
        if username in schedules:
            del schedules[username]
            save_schedules(schedules)
            logging.info(f"Agendamento de reativação para '{username}' removido por reativação manual.")
    logging.info(f"Conta '{username}' foi {action_message} por '{session.get('ad_user')}'.")
    flash(f"Conta do usuário foi {action_message} com sucesso.", "success")
    return redirect(url_for('view_user', username=username))
@app.route('/disable_user_temp/<username>', methods=['POST'])
@require_auth
@require_permission(action='can_disable')
@handle_ldap_exceptions
def disable_user_temp(username):
    days = int(request.args.get('days'))
    if days <= 0:
        flash("O número de dias deve ser positivo.", "error")
        return redirect(url_for('view_user', username=username))
    conn = get_service_account_connection()
    user = get_user_by_samaccountname(conn, username, ['userAccountControl', 'distinguishedName'])
    if not user:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for('manage_users'))
    uac = user.userAccountControl.value
    if not (uac & 2):
        conn.modify(user.distinguishedName.value, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [str(uac + 2)])]})
    schedules = load_schedules()
    reactivation_date = (date.today() + timedelta(days=days)).isoformat()
    schedules[username] = reactivation_date
    save_schedules(schedules)
    logging.info(f"Conta de '{username}' desativada por {days} dias por '{session.get('ad_user')}'. Reativação: {reactivation_date}.")
    flash(f"Conta do usuário desativada. Reativação agendada para {reactivation_date}.", "success")
    return redirect(url_for('view_user', username=username))
@app.route('/reset_password/<username>', methods=['POST'])
@require_auth
@require_permission(action='can_reset_password')
@handle_ldap_exceptions
def reset_password(username):
    conn = get_service_account_connection()
    user = get_user_by_samaccountname(conn, username, ['distinguishedName'])
    if not user:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for('manage_users'))
    config = load_config()
    default_password = config.get('DEFAULT_PASSWORD')
    if not default_password:
        flash("A senha padrão não está definida.", "error")
        return redirect(url_for('view_user', username=username))
    conn.extend.microsoft.modify_password(user.distinguishedName.value, default_password)
    conn.modify(user.distinguishedName.value, {'pwdLastSet': [(ldap3.MODIFY_REPLACE, [0])]})
    logging.info(f"Senha para '{username}' resetada por '{session.get('ad_user')}'.")
    flash(f"Senha resetada. Nova senha temporária: {default_password}", "success")
    return redirect(url_for('view_user', username=username))
@app.route('/edit_user/<username>', methods=['GET', 'POST'])
@require_auth
@require_permission(action='can_edit')
@handle_ldap_exceptions
def edit_user(username):
    conn = get_read_connection()
    user = get_user_by_samaccountname(conn, username)
    if not user:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for('manage_users'))
    form = EditUserForm()
    editable_fields = {f.name for f in form if f.type not in ('CSRFTokenField', 'SubmitField') and check_permission(field=f.name)}
    if request.method == 'POST':
        for field_name, field in form._fields.items():
            if field_name not in editable_fields and field_name not in ['csrf_token', 'submit']:
                field.validators = []
    if form.validate_on_submit():
        service_conn = get_service_account_connection()
        changes = {}
        field_to_attr = {'first_name': 'givenName', 'last_name': 'sn', 'initials': 'initials', 'display_name': 'displayName', 'description': 'description', 'office': 'physicalDeliveryOfficeName', 'telephone': 'telephoneNumber', 'email': 'mail', 'web_page': 'wWWHomePage', 'street': 'streetAddress', 'post_office_box': 'postOfficeBox', 'city': 'l', 'state': 'st', 'zip_code': 'postalCode', 'home_phone': 'homePhone', 'pager': 'pager', 'mobile': 'mobile', 'fax': 'facsimileTelephoneNumber', 'title': 'title', 'department': 'department', 'company': 'company'}
        for field_name in editable_fields:
            if field_name in field_to_attr:
                attr_name = field_to_attr[field_name]
                submitted_value = getattr(form, field_name).data
                original_value = get_attr_value(user, attr_name)
                if submitted_value != original_value:
                    changes[attr_name] = [(ldap3.MODIFY_REPLACE, [submitted_value or ''])]
        if changes:
            service_conn.modify(user.distinguishedName.value, changes)
            if service_conn.result['description'] == 'success':
                flash('Usuário atualizado com sucesso!', 'success')
                logging.info(f"Usuário '{username}' atualizado por '{session.get('ad_user')}'. Campos: {list(changes.keys())}")
            else:
                flash(f"Erro ao atualizar usuário: {service_conn.result['message']}", 'error')
        else:
            flash("Nenhum valor foi alterado.", "info")
        return redirect(url_for('view_user', username=username))
    for field in form:
        field_to_attr = {'first_name': 'givenName', 'last_name': 'sn', 'initials': 'initials', 'display_name': 'displayName', 'description': 'description', 'office': 'physicalDeliveryOfficeName', 'telephone': 'telephoneNumber', 'email': 'mail', 'web_page': 'wWWHomePage', 'street': 'streetAddress', 'post_office_box': 'postOfficeBox', 'city': 'l', 'state': 'st', 'zip_code': 'postalCode', 'home_phone': 'homePhone', 'pager': 'pager', 'mobile': 'mobile', 'fax': 'facsimileTelephoneNumber', 'title': 'title', 'department': 'department', 'company': 'company'}
        attr_name = field_to_attr.get(field.name)
        if attr_name:
            field.data = get_attr_value(user, attr_name)
    return render_template('edit_user.html', form=form, username=username, user_name=get_attr_value(user, 'displayName'), editable_fields=editable_fields)

# ==============================================================================
# Rotas Apenas para Admin
# ==============================================================================
@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if load_user() is not None:
        flash('Um usuário administrador já existe.', 'danger')
        return redirect(url_for('admin_login'))
    form = AdminRegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        save_user({'username': form.username.data, 'password_hash': hashed_password})
        flash('Usuário administrador criado com sucesso! Por favor, faça o login.', 'success')
        return redirect(url_for('admin_login'))
    return render_template('admin/register.html', form=form)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        admin_user = load_user()
        if admin_user and admin_user['username'] == form.username.data and check_password_hash(admin_user['password_hash'], form.password.data):
            session['master_admin'] = admin_user['username']
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Nome de usuário ou senha do administrador inválidos.', 'danger')
    return render_template('admin/login.html', form=form)

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'master_admin' not in session: return redirect(url_for('admin_login'))
    return render_template('admin/dashboard.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('master_admin', None)
    flash('Você foi desconectado do painel de administração.', 'info')
    return redirect(url_for('admin_login'))

@app.route('/admin/change_password', methods=['GET', 'POST'])
def admin_change_password():
    if 'master_admin' not in session: return redirect(url_for('admin_login'))
    form = AdminChangePasswordForm()
    if form.validate_on_submit():
        admin_user = load_user()
        if check_password_hash(admin_user['password_hash'], form.current_password.data):
            new_hashed_password = generate_password_hash(form.new_password.data)
            admin_user['password_hash'] = new_hashed_password
            save_user(admin_user)
            flash('Sua senha foi alterada com sucesso!', 'success')
            return redirect(url_for('admin_dashboard'))
        else: flash('A senha atual está incorreta.', 'danger')
    return render_template('admin/change_password.html', form=form)

@app.route('/admin/config', methods=['GET', 'POST'])
def config():
    if 'master_admin' not in session: return redirect(url_for('admin_login'))
    form = ConfigForm()
    if form.validate_on_submit():
        current_config = load_config()
        new_config = {'AD_SERVER': form.ad_server.data, 'USE_LDAPS': form.use_ldaps.data, 'AD_DOMAIN': form.ad_domain.data, 'AD_SEARCH_BASE': form.ad_search_base.data, 'SSO_ENABLED': form.sso_enabled.data, 'SERVICE_ACCOUNT_USER': form.service_account_user.data}
        if form.default_password.data: new_config['DEFAULT_PASSWORD'] = form.default_password.data
        elif 'DEFAULT_PASSWORD' in current_config: new_config['DEFAULT_PASSWORD'] = current_config['DEFAULT_PASSWORD']
        if form.service_account_password.data: new_config['SERVICE_ACCOUNT_PASSWORD'] = form.service_account_password.data
        elif 'SERVICE_ACCOUNT_PASSWORD' in current_config: new_config['SERVICE_ACCOUNT_PASSWORD'] = current_config['SERVICE_ACCOUNT_PASSWORD']
        save_config(new_config)
        flash('Configuração salva com sucesso!', 'success')
        return redirect(url_for('config'))
    current_config = load_config()
    form.ad_server.data = current_config.get('AD_SERVER')
    form.use_ldaps.data = current_config.get('USE_LDAPS', False)
    form.ad_domain.data = current_config.get('AD_DOMAIN')
    form.ad_search_base.data = current_config.get('AD_SEARCH_BASE')
    form.sso_enabled.data = current_config.get('SSO_ENABLED', False)
    form.service_account_user.data = current_config.get('SERVICE_ACCOUNT_USER')
    return render_template('admin/config.html', form=form)

@app.route('/admin/logs', methods=['GET', 'POST'])
def admin_logs():
    if 'master_admin' not in session:
        return redirect(url_for('admin_login'))

    search_form = LogSearchForm()

    try:
        available_logs = sorted([f for f in os.listdir(logs_dir) if f.endswith('.log')])
    except FileNotFoundError:
        available_logs = []

    selected_log_file = request.args.get('logfile', 'ad_creator.log')

    if selected_log_file not in available_logs:
        selected_log_file = 'ad_creator.log' if 'ad_creator.log' in available_logs else (available_logs[0] if available_logs else None)

    log_content = []
    if selected_log_file:
        try:
            current_log_path = os.path.join(logs_dir, selected_log_file)
            with open(current_log_path, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()

            log_entries = []
            for line in all_lines:
                match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d{3} - \w+ - (.*)", line)
                if match:
                    log_entries.append({"timestamp": match.group(1), "message": match.group(2)})
                else:
                    log_entries.append({"timestamp": "N/A", "message": line.strip()})

            log_content = list(reversed(log_entries))

            if request.method == 'POST' and search_form.validate_on_submit():
                query = search_form.search_query.data.lower()
                if query:
                    log_content = [entry for entry in log_content if query in entry['message'].lower()]

        except Exception as e:
            flash(f"Erro ao ler o arquivo de log '{selected_log_file}': {e}", "error")

    return render_template(
        'admin/logs.html',
        logs=log_content,
        search_form=search_form,
        available_logs=available_logs,
        current_log_file=selected_log_file
    )

@app.route('/admin/permissions', methods=['GET', 'POST'])
@handle_ldap_exceptions
def permissions():
    if 'master_admin' not in session: return redirect(url_for('admin_login'))
    search_form, permissions_form, groups = GroupSearchForm(), FlaskForm(), []
    available_fields = {'first_name': 'Nome', 'last_name': 'Sobrenome', 'initials': 'Iniciais', 'display_name': 'Nome de Exibição', 'description': 'Descrição', 'office': 'Escritório', 'telephone': 'Telefone Principal', 'email': 'E-mail', 'web_page': 'Página da Web', 'street': 'Rua', 'post_office_box': 'Caixa Postal', 'city': 'Cidade', 'state': 'Estado/Província', 'zip_code': 'CEP', 'home_phone': 'Telefone Residencial', 'pager': 'Pager', 'mobile': 'Celular', 'fax': 'Fax', 'title': 'Cargo', 'department': 'Departamento', 'company': 'Empresa'}
    conn = get_service_account_connection()
    config = load_config()
    search_base = config.get('AD_SEARCH_BASE')
    if search_form.validate_on_submit() and search_form.submit.data:
        query = search_form.search_query.data
        safe_query = escape_filter_chars(query)
        search_filter = f"(&(objectClass=group)(cn=*{safe_query}*))"
        conn.search(search_base, search_filter, attributes=['cn'])
        groups = sorted([g.cn.value for g in conn.entries])
        if not groups: flash(f"Nenhum grupo encontrado com o nome '{query}'.", "info")
    if permissions_form.validate_on_submit() and request.form.get('save_permissions'):
        permissions_data = load_permissions()
        for group in request.form.getlist('searched_groups'):
            perm_type = request.form.get(f'{group}_perm_type')
            if perm_type == 'full': permissions_data[group] = {'type': 'full'}
            elif perm_type == 'custom':
                actions = {'can_create': f'{group}_can_create' in request.form, 'can_disable': f'{group}_can_disable' in request.form, 'can_reset_password': f'{group}_can_reset_password' in request.form, 'can_edit': f'{group}_can_edit' in request.form, 'can_manage_groups': f'{group}_can_manage_groups' in request.form}
                fields = [field for field in available_fields if f'{group}_field_{field}' in request.form]
                permissions_data[group] = {'type': 'custom', 'actions': actions, 'fields': fields}
            elif perm_type == 'none': permissions_data[group] = {'type': 'none'}
        save_permissions(permissions_data)
        flash('Permissões salvas com sucesso!', 'success')
        search_query = request.form.get('search_query_hidden', '')
        if search_query:
             safe_query = escape_filter_chars(search_query)
             search_filter = f"(&(objectClass=group)(cn=*{safe_query}*))"
             conn.search(search_base, search_filter, attributes=['cn'])
             groups = sorted([g.cn.value for g in conn.entries])
    permissions_data = load_permissions()
    return render_template('admin/permissions.html', search_form=search_form, permissions_form=permissions_form, groups=groups, permissions=permissions_data, available_fields=available_fields)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)