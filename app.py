import os
import logging
from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify, Response
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
import io
import csv

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
    """Gera uma chave e a salva em 'secret.key'."""
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

def load_key():
    """Carrega a chave de 'secret.key'."""
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
        with open(user_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def save_user(user_data):
    user_path = os.path.join(basedir, 'user.json')
    with open(user_path, 'w', encoding='utf-8') as f:
        json.dump(user_data, f, indent=4)

def load_schedules():
    try:
        with open(SCHEDULE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_schedules(schedules):
    with open(SCHEDULE_FILE, 'w', encoding='utf-8') as f:
        json.dump(schedules, f, indent=4)

def load_permissions():
    try:
        with open(PERMISSIONS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_permissions(permissions):
    with open(PERMISSIONS_FILE, 'w', encoding='utf-8') as f:
        json.dump(permissions, f, indent=4)

# ==============================================================================
# Lógica de Permissões
# ==============================================================================
def get_user_access_level(user_groups):
    permissions = load_permissions()
    if not user_groups or not permissions:
        return 'none'
    access_levels = {'none'}
    for group in user_groups:
        rule = permissions.get(group, {})
        access_levels.add(rule.get('type', 'none'))
    if 'full' in access_levels: return 'full'
    if 'custom' in access_levels: return 'custom'
    return 'none'

def check_permission(action=None, field=None, view=None):
    access_level = session.get('access_level')
    if access_level == 'full': return True
    if access_level == 'none': return False
    user_groups = session.get('user_groups', [])
    permissions = load_permissions()
    if not permissions or not user_groups: return False
    for group in user_groups:
        rule = permissions.get(group)
        if rule and rule.get('type') == 'custom':
            if action and rule.get('actions', {}).get(action): return True
            if field and field in rule.get('fields', []): return True
            if view and rule.get('views', {}).get(view): return True
    return False

def require_permission(action=None, field=None, view=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not check_permission(action=action, field=field, view=view):
                flash('Você não tem permissão para realizar esta ação.', 'error')
                return redirect(request.referrer or url_for('dashboard'))
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

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'ad_user' not in session:
            flash("Sua sessão expirou. Por favor, faça login novamente.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_permission_checker():
    return dict(check_permission=check_permission)

def get_attr_value(user, attr):
    return user[attr].value if attr in user and user[attr].value is not None else ''

# ==============================================================================
# Funções Auxiliares do Active Directory
# ==============================================================================
def get_service_account_connection():
    config = load_config()
    user = config.get('SERVICE_ACCOUNT_USER')
    password = config.get('SERVICE_ACCOUNT_PASSWORD')
    if not user or not password:
        raise Exception("Conta de serviço não configurada.")
    return get_ldap_connection(user, password)

def get_read_connection():
    try:
        return get_service_account_connection()
    except Exception as e:
        raise Exception(f"É necessária uma conta de serviço para operações de leitura. Erro: {e}")

def get_ldap_connection(user, password):
    config = load_config()
    ad_server = config.get('AD_SERVER')
    use_ldaps = config.get('USE_LDAPS', False)
    if not ad_server:
        raise Exception("Servidor AD não configurado.")
    server = Server(ad_server, use_ssl=use_ldaps, get_info=ALL)
    return Connection(server, user=user, password=password, auto_bind=True)

def get_user_by_samaccountname(conn, sam_account_name, attributes=None):
    if attributes is None: attributes = ldap3.ALL_ATTRIBUTES
    config = load_config()
    search_base = config.get('AD_SEARCH_BASE')
    conn.search(search_base, f'(sAMAccountName={sam_account_name})', attributes=attributes)
    return conn.entries[0] if conn.entries else None

# ==============================================================================
# Funções do Dashboard (Incluindo Placeholders)
# ==============================================================================
def get_dashboard_stats(conn):
    stats = {'enabled_users': 0, 'disabled_users': 0}
    config = load_config()
    search_base = config.get('AD_SEARCH_BASE')
    if not search_base: return stats
    try:
        entry_generator = conn.extend.standard.paged_search(search_base, '(&(objectClass=user)(objectCategory=person))', attributes=['userAccountControl'], paged_size=500)
        for entry in entry_generator:
            uac = entry.get('attributes', {}).get('userAccountControl')
            if uac and (int(uac) & 2):
                stats['disabled_users'] += 1
            else:
                stats['enabled_users'] += 1
    except Exception as e:
        logging.error(f"Erro ao buscar estatísticas do dashboard: {e}", exc_info=True)
    return stats

def get_pending_reactivations(days=7):
    schedules = load_schedules()
    count = 0
    today = date.today()
    limit_date = today + timedelta(days=days)
    for _, date_str in schedules.items():
        try:
            reactivation_date = date.fromisoformat(date_str)
            if today <= reactivation_date < limit_date:
                count += 1
        except (ValueError, TypeError):
            continue
    return count

def filetime_to_datetime(ft):
    EPOCH_AS_FILETIME = 116444736000000000
    HUNDREDS_OF_NANOSECONDS = 10000000
    if ft is None or int(ft) == 0 or int(ft) == 9223372036854775807:
        return None
    return datetime.fromtimestamp((int(ft) - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS, tz=timezone.utc)

def get_expiring_passwords(conn, days=15):
    expiring_users = []
    config = load_config()
    search_base = config.get('AD_SEARCH_BASE')
    if not search_base: return expiring_users
    try:
        search_filter = "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=65536)))"
        attributes = ['cn', 'sAMAccountName', 'msDS-UserPasswordExpiryTimeComputed']
        now_utc = datetime.now(timezone.utc)
        expiration_limit = now_utc + timedelta(days=days)
        entry_generator = conn.extend.standard.paged_search(search_base, search_filter, attributes=attributes, paged_size=1000)
        for entry in entry_generator:
            expiry_time_ft = entry.get('attributes', {}).get('msDS-UserPasswordExpiryTimeComputed')
            if expiry_time_ft:
                expiry_datetime = filetime_to_datetime(expiry_time_ft)
                if expiry_datetime and now_utc < expiry_datetime < expiration_limit:
                    delta = expiry_datetime - now_utc
                    expiring_users.append({'cn': entry.get('attributes', {}).get('cn'), 'sam': entry.get('attributes', {}).get('sAMAccountName'), 'expires_in_days': delta.days + 1})
    except Exception as e:
        logging.error(f"Erro ao buscar senhas expirando: {e}", exc_info=True)
    return sorted(expiring_users, key=lambda x: x['expires_in_days'])

# PLACEHOLDER FUNCTIONS
def get_deactivated_last_7_days():
    return {'count': 0, 'users': []}

def get_scheduled_deactivations(days=7):
    return {'count': 0, 'users': []}

# ==============================================================================
# Rotas Principais
# ==============================================================================
@app.route('/')
@require_auth
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@require_auth
def dashboard():
    dashboard_data = {}
    try:
        conn = get_read_connection()
        if check_permission(view='can_view_user_stats'):
            user_stats_raw = get_dashboard_stats(conn)
            dashboard_data['user_stats'] = {'active': user_stats_raw.get('enabled_users', 0), 'disabled': user_stats_raw.get('disabled_users', 0)}
        if check_permission(view='can_view_deactivated_last_7_days'):
            dashboard_data['deactivated_last_7_days'] = get_deactivated_last_7_days()
        if check_permission(view='can_view_scheduled_deactivations'):
            dashboard_data['scheduled_deactivations'] = get_scheduled_deactivations(days=7)
        if check_permission(view='can_view_pending_reactivations'):
            dashboard_data['pending_reactivations'] = {'count': get_pending_reactivations(days=7)}
        if check_permission(view='can_view_expiring_passwords'):
            dashboard_data['expiring_passwords'] = get_expiring_passwords(conn, days=5)
    except Exception as e:
        flash(f"Erro ao carregar dados do dashboard: {e}", "error")
        logging.error(f"Erro ao carregar dados do dashboard: {e}", exc_info=True)

    return render_template('dashboard.html', dashboard_data=dashboard_data)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = FlaskForm() # Simplified form for login
    if request.method == 'POST':
        try:
            config = load_config()
            ad_domain = config.get('AD_DOMAIN')
            username = request.form['username']
            password = request.form['password']
            full_username = f'{ad_domain}\\{username}'
            conn = get_ldap_connection(full_username, password)
            user_object = get_user_by_samaccountname(conn, username, attributes=['memberOf', 'displayName', 'sAMAccountName'])
            if not user_object:
                flash('Nome de usuário ou senha inválidos.', 'error')
                return redirect(url_for('login'))
            user_groups = [g.split(',')[0].split('=')[1] for g in user_object.memberOf.values] if 'memberOf' in user_object and user_object.memberOf.value else []
            session['ad_user'] = user_object.entry_dn
            session['user_display_name'] = get_attr_value(user_object, 'displayName') or username
            session['user_groups'] = user_groups
            session['access_level'] = get_user_access_level(user_groups)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
            flash('Usuário ou senha incorretos.', 'error')
        except Exception as e:
            flash('Erro de conexão com o servidor.', 'error')
            logging.error(f"Erro de login: {e}", exc_info=True)
    return render_template('login.html', form=form, sso_enabled=load_config().get('SSO_ENABLED', False))


@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu do sistema.', 'info')
    return redirect(url_for('login'))

# ==============================================================================
# Rota de Exportação (Corrigida)
# ==============================================================================
@app.route('/export_ad_data')
@require_auth
@require_permission(view='can_export_data')
def export_ad_data():
    try:
        conn = get_service_account_connection()
        config = load_config()
        search_base = config.get('AD_SEARCH_BASE')
        required_attributes = [
            'givenName', 'sn', 'initials', 'displayName', 'description',
            'physicalDeliveryOfficeName', 'telephoneNumber', 'mail', 'wWWHomePage',
            'streetAddress', 'postOfficeBox', 'l', 'st', 'postalCode',
            'homePhone', 'pager', 'mobile', 'facsimileTelephoneNumber',
            'title', 'department', 'company'
        ]
        filter_parts = [f'({attr}=*)' for attr in required_attributes]
        search_filter = f"(&(objectClass=user)(objectCategory=person){''.join(filter_parts)})"

        csv_header = ['Nome Completo', 'Login', 'Departamento', 'Cargo', 'Email', 'Telefone', 'Celular', 'Escritório', 'Descrição', 'Status da Conta', 'Data de Criação', 'Último Logon']
        attributes_to_fetch = ['displayName', 'sAMAccountName', 'department', 'title', 'mail', 'telephoneNumber', 'mobile', 'physicalDeliveryOfficeName', 'description', 'userAccountControl', 'whenCreated', 'lastLogonTimestamp']

        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)
        writer.writerow(csv_header)

        entry_generator = conn.extend.standard.paged_search(
            search_base=search_base,
            search_filter=search_filter,
            attributes=attributes_to_fetch,
            paged_size=500
        )

        for entry in entry_generator:
            row = []
            for attr in attributes_to_fetch:
                value = get_attr_value(entry.get('attributes',{}), attr)
                if attr == 'userAccountControl':
                    value = "Desativado" if int(value or 0) & 2 else "Ativo"
                elif attr in ['whenCreated', 'lastLogonTimestamp']:
                    dt_obj = filetime_to_datetime(value)
                    value = dt_obj.strftime('%d/%m/%Y %H:%M:%S') if dt_obj else 'Nunca'
                row.append(str(value) or '')
            writer.writerow(row)

        output.seek(0)
        return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=export_ad_data.csv"})
    except Exception as e:
        logging.error(f"Erro na exportação de dados: {e}", exc_info=True)
        flash("Ocorreu um erro crítico ao gerar o arquivo de exportação.", "error")
        return redirect(url_for('dashboard'))

# ==============================================================================
# Rotas de Administração (Corrigida)
# ==============================================================================
@app.route('/admin/permissions', methods=['GET', 'POST'])
def permissions():
    if 'master_admin' not in session: return redirect(url_for('admin_login'))

    available_fields = {
        'first_name': 'Nome', 'last_name': 'Sobrenome', 'initials': 'Iniciais',
        'display_name': 'Nome de Exibição', 'description': 'Descrição', 'office': 'Escritório',
        'telephone': 'Telefone Principal', 'email': 'E-mail', 'web_page': 'Página da Web',
        'street': 'Rua', 'post_office_box': 'Caixa Postal', 'city': 'Cidade',
        'state': 'Estado/Província', 'zip_code': 'CEP', 'home_phone': 'Telefone Residencial',
        'pager': 'Pager', 'mobile': 'Celular', 'fax': 'Fax', 'title': 'Cargo',
        'department': 'Departamento', 'company': 'Empresa'
    }
    # Dicionário que estava faltando
    available_views = {
        'can_view_user_stats': 'Estatísticas de Usuários',
        'can_view_deactivated_last_7_days': 'Desativados (Últimos 7 dias)',
        'can_view_scheduled_deactivations': 'Desativações Agendadas',
        'can_view_pending_reactivations': 'Reativações Agendadas',
        'can_view_expiring_passwords': 'Senhas Expirando',
        'can_export_data': 'Exportar Base AD'
    }

    search_form = GroupSearchForm()
    permissions_form = FlaskForm() # Para o token CSRF
    groups = []

    try:
        conn = get_service_account_connection()
        config = load_config()
        search_base = config.get('AD_SEARCH_BASE')

        if search_form.validate_on_submit():
            query = search_form.search_query.data
            conn.search(search_base, f"(&(objectClass=group)(cn=*{query}*))", attributes=['cn'])
            groups = sorted([g.cn.value for g in conn.entries])
            if not groups: flash(f"Nenhum grupo encontrado com '{query}'.", "info")

        if request.method == 'POST' and request.form.get('save_permissions'):
            permissions_data = load_permissions()
            searched_groups = request.form.getlist('searched_groups')
            for group in searched_groups:
                perm_type = request.form.get(f'{group}_perm_type')
                if perm_type == 'full':
                    permissions_data[group] = {'type': 'full'}
                elif perm_type == 'custom':
                    permissions_data[group] = {
                        'type': 'custom',
                        'actions': {k: f'{group}_action_{k}' in request.form for k in ['can_create', 'can_disable', 'can_reset_password', 'can_edit', 'can_manage_groups']},
                        'views': {k: f'{group}_view_{k}' in request.form for k in available_views},
                        'fields': [k for k in available_fields if f'{group}_field_{k}' in request.form]
                    }
                else: # none
                    permissions_data[group] = {'type': 'none'}
            save_permissions(permissions_data)
            flash('Permissões salvas com sucesso!', 'success')
            # Re-run search to keep the groups on the page
            query = request.form.get('search_query_hidden', '')
            if query:
                conn.search(search_base, f"(&(objectClass=group)(cn=*{query}*))", attributes=['cn'])
                groups = sorted([g.cn.value for g in conn.entries])

        return render_template(
            'admin/permissions.html',
            search_form=search_form,
            permissions_form=permissions_form,
            groups=groups,
            permissions=load_permissions(),
            available_fields=available_fields,
            available_views=available_views # Passando o dicionário para o template
        )

    except Exception as e:
        flash(f"Erro ao carregar a página de permissões: {e}", "error")
        logging.error(f"Erro em /admin/permissions: {e}", exc_info=True)
        return redirect(url_for('admin_dashboard'))

# Adicionando as classes de formulário que podem estar faltando
class GroupSearchForm(FlaskForm):
    search_query = StringField('Buscar Grupo por Nome', validators=[DataRequired()])
    submit = SubmitField('Buscar')

class AdminLoginForm(FlaskForm):
    username = StringField('Nome de Usuário do Admin', validators=[DataRequired()])
    password = PasswordField('Senha do Admin', validators=[DataRequired()])
    submit = SubmitField('Entrar')

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
    if 'master_admin' not in session:
        return redirect(url_for('admin_login'))
    return render_template('admin/dashboard.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)