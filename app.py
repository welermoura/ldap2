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
# Funções Auxiliares (User, Schedule, Permissions)
# ==============================================================================
def load_user():
    user_path = os.path.join(basedir, 'user.json')
    try:
        with open(user_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def load_schedules():
    try:
        with open(SCHEDULE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def load_permissions():
    try:
        with open(PERMISSIONS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

# ==============================================================================
# Lógica de Permissões
# ==============================================================================
def get_user_access_level(user_groups):
    permissions = load_permissions()
    if not user_groups or not permissions: return 'none'
    access_levels = {'none'}
    for group in user_groups:
        access_levels.add(permissions.get(group, {}).get('type', 'none'))
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
    # Ajustado para lidar com dicionários e objetos
    if isinstance(user, dict):
        return user.get(attr, '')
    return getattr(user, attr, {}).get('value', '') if hasattr(user, attr) else ''


# ==============================================================================
# Conexão com LDAP
# ==============================================================================
def get_ldap_connection(user, password):
    config = load_config()
    server = Server(config.get('AD_SERVER'), use_ssl=config.get('USE_LDAPS', False), get_info=ALL)
    return Connection(server, user=user, password=password, auto_bind=True)

def get_service_account_connection():
    config = load_config()
    user = config.get('SERVICE_ACCOUNT_USER')
    password = config.get('SERVICE_ACCOUNT_PASSWORD')
    if not user or not password: raise Exception("Conta de serviço não configurada.")
    return get_ldap_connection(user, password)

def get_read_connection():
    return get_service_account_connection()

def get_user_by_samaccountname(conn, sam_account_name, attributes=None):
    if attributes is None: attributes = ldap3.ALL_ATTRIBUTES
    search_base = load_config().get('AD_SEARCH_BASE')
    conn.search(search_base, f'(sAMAccountName={sam_account_name})', attributes=attributes)
    return conn.entries[0] if conn.entries else None

# ==============================================================================
# Funções do Dashboard
# ==============================================================================
def get_dashboard_stats(conn):
    stats = {'enabled_users': 0, 'disabled_users': 0}
    try:
        search_base = load_config().get('AD_SEARCH_BASE')
        entry_generator = conn.extend.standard.paged_search(search_base, '(&(objectClass=user)(objectCategory=person))', attributes=['userAccountControl'], paged_size=500)
        for entry in entry_generator:
            uac = entry.userAccountControl.value if 'userAccountControl' in entry else 0
            if uac & 2: stats['disabled_users'] += 1
            else: stats['enabled_users'] += 1
    except Exception as e:
        logging.error(f"Erro em get_dashboard_stats: {e}", exc_info=True)
    return stats

def get_pending_reactivations(days=7):
    count = 0
    today = date.today()
    limit = today + timedelta(days=days)
    for _, date_str in load_schedules().items():
        try:
            if today <= date.fromisoformat(date_str) < limit:
                count += 1
        except (ValueError, TypeError): continue
    return count

def filetime_to_datetime(ft):
    if not ft or int(ft) in [0, 9223372036854775807]: return None
    return datetime.fromtimestamp((int(ft) - 116444736000000000) / 10000000, tz=timezone.utc)

def get_expiring_passwords(conn, days=15):
    users = []
    try:
        search_base = load_config().get('AD_SEARCH_BASE')
        now_utc = datetime.now(timezone.utc)
        limit = now_utc + timedelta(days=days)
        search_filter = "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=65536)))"
        entry_generator = conn.extend.standard.paged_search(search_base, search_filter, attributes=['cn', 'sAMAccountName', 'msDS-UserPasswordExpiryTimeComputed'], paged_size=1000)
        for entry in entry_generator:
            expiry_dt = filetime_to_datetime(entry['msDS-UserPasswordExpiryTimeComputed'].value)
            if expiry_dt and now_utc < expiry_dt < limit:
                users.append({'cn': entry.cn.value, 'sam': entry.sAMAccountName.value, 'expires_in_days': (expiry_dt - now_utc).days + 1})
    except Exception as e:
        logging.error(f"Erro em get_expiring_passwords: {e}", exc_info=True)
    return sorted(users, key=lambda x: x['expires_in_days'])

def get_deactivated_last_7_days(): return {'count': 0, 'users': []}
def get_scheduled_deactivations(days=7): return {'count': 0, 'users': []}

# ==============================================================================
# Rotas
# ==============================================================================
@app.route('/')
@require_auth
def index():
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = FlaskForm()
    if request.method == 'POST':
        try:
            config = load_config()
            username, password = request.form['username'], request.form['password']
            conn = get_ldap_connection(f"{config.get('AD_DOMAIN')}\\{username}", password)
            user_obj = get_user_by_samaccountname(conn, username, ['memberOf', 'displayName'])
            if not user_obj:
                flash('Usuário ou senha inválidos.', 'error')
                return redirect(url_for('login'))

            groups = [g.split(',')[0].split('=')[1] for g in user_obj.memberOf.values or []]
            session.update({
                'ad_user': user_obj.entry_dn,
                'user_display_name': user_obj.displayName.value or username,
                'user_groups': groups,
                'access_level': get_user_access_level(groups)
            })
            return redirect(url_for('dashboard'))
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
            flash('Usuário ou senha incorretos.', 'error')
        except Exception as e:
            flash(f'Erro de conexão: {e}', 'error')
            logging.error(f"Erro de login para {request.form.get('username')}: {e}", exc_info=True)
    return render_template('login.html', form=form, sso_enabled=load_config().get('SSO_ENABLED'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu do sistema.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@require_auth
def dashboard():
    data = {}
    try:
        conn = get_read_connection()
        if check_permission(view='can_view_user_stats'):
            stats = get_dashboard_stats(conn)
            data['user_stats'] = {'active': stats.get('enabled_users', 0), 'disabled': stats.get('disabled_users', 0)}
        if check_permission(view='can_view_deactivated_last_7_days'):
            data['deactivated_last_7_days'] = get_deactivated_last_7_days()
        if check_permission(view='can_view_scheduled_deactivations'):
            data['scheduled_deactivations'] = get_scheduled_deactivations(days=7)
        if check_permission(view='can_view_pending_reactivations'):
            data['pending_reactivations'] = {'count': get_pending_reactivations(days=7)}
        if check_permission(view='can_view_expiring_passwords'):
            data['expiring_passwords'] = get_expiring_passwords(conn, days=5)
    except Exception as e:
        flash(f"Erro ao carregar dados do dashboard: {e}", "error")
        logging.error(f"Erro no dashboard: {e}", exc_info=True)
    return render_template('dashboard.html', dashboard_data=data)

@app.route('/catalogo')
@require_auth
def address_book():
    users = []
    try:
        conn = get_read_connection()
        search_base = load_config().get('AD_SEARCH_BASE')
        search_filter = "(&(objectClass=user)(objectCategory=person)(displayName=*)(title=*)(department=*)(telephoneNumber=*)(mail=*)(company=*)(l=*))"
        attributes = ['displayName', 'title', 'department', 'telephoneNumber', 'mail', 'company', 'l', 'sAMAccountName']
        entry_generator = conn.extend.standard.paged_search(search_base, search_filter, attributes=attributes, paged_size=1000, generator=True)
        users = sorted([entry['attributes'] for entry in entry_generator], key=lambda u: u.get('displayName', [''])[0].lower())
    except Exception as e:
        flash("Erro ao carregar o catálogo de endereços.", "error")
        logging.error(f"Erro em address_book: {e}", exc_info=True)
    return render_template('catalogo.html', users=users)

@app.route('/export_ad_data')
@require_auth
def export_ad_data():
    try:
        conn = get_service_account_connection()
        search_base = load_config().get('AD_SEARCH_BASE')
        required_attrs = ['givenName', 'sn', 'initials', 'displayName', 'description', 'physicalDeliveryOfficeName', 'telephoneNumber', 'mail', 'wWWHomePage', 'streetAddress', 'postOfficeBox', 'l', 'st', 'postalCode', 'homePhone', 'pager', 'mobile', 'facsimileTelephoneNumber', 'title', 'department', 'company']
        filter_parts = [f'({attr}=*)' for attr in required_attrs]
        search_filter = f"(&(objectClass=user)(objectCategory=person){''.join(filter_parts)})"

        csv_header = ['Nome Completo', 'Login', 'Departamento', 'Cargo', 'Email', 'Telefone', 'Celular', 'Escritório', 'Descrição', 'Status da Conta', 'Data de Criação', 'Último Logon']
        fetch_attrs = ['displayName', 'sAMAccountName', 'department', 'title', 'mail', 'telephoneNumber', 'mobile', 'physicalDeliveryOfficeName', 'description', 'userAccountControl', 'whenCreated', 'lastLogonTimestamp']

        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)
        writer.writerow(csv_header)

        entry_generator = conn.extend.standard.paged_search(search_base, search_filter, attributes=fetch_attrs, paged_size=500)
        for entry in entry_generator:
            row = []
            for attr in fetch_attrs:
                value = entry[attr].value if attr in entry and entry[attr].value is not None else ''
                if attr == 'userAccountControl': value = "Desativado" if int(value or 0) & 2 else "Ativo"
                elif attr in ['whenCreated', 'lastLogonTimestamp']:
                    dt = filetime_to_datetime(value)
                    value = dt.strftime('%d/%m/%Y %H:%M:%S') if dt else 'Nunca'
                row.append(str(value))
            writer.writerow(row)
        output.seek(0)
        return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=export_ad_data.csv"})
    except Exception as e:
        logging.error(f"Erro na exportação: {e}", exc_info=True)
        flash("Erro crítico ao gerar a exportação.", "error")
        return redirect(url_for('dashboard'))

# Admin routes and forms
class GroupSearchForm(FlaskForm):
    search_query = StringField('Buscar Grupo', validators=[DataRequired()])
    submit = SubmitField('Buscar')

class AdminLoginForm(FlaskForm):
    username = StringField('Usuário Admin', validators=[DataRequired()])
    password = PasswordField('Senha Admin', validators=[DataRequired()])
    submit = SubmitField('Entrar')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        user = load_user()
        if user and user['username'] == form.username.data and check_password_hash(user['password_hash'], form.password.data):
            session['master_admin'] = user['username']
            return redirect(url_for('admin_dashboard'))
        flash('Credenciais de admin inválidas.', 'danger')
    return render_template('admin/login.html', form=form)

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'master_admin' not in session: return redirect(url_for('admin_login'))
    return render_template('admin/dashboard.html')

@app.route('/admin/permissions', methods=['GET', 'POST'])
def permissions():
    if 'master_admin' not in session: return redirect(url_for('admin_login'))

    available_fields = {'first_name': 'Nome', 'last_name': 'Sobrenome', 'initials': 'Iniciais', 'display_name': 'Nome de Exibição', 'description': 'Descrição', 'office': 'Escritório', 'telephone': 'Telefone', 'email': 'E-mail', 'web_page': 'Página Web', 'street': 'Rua', 'post_office_box': 'Caixa Postal', 'city': 'Cidade', 'state': 'Estado', 'zip_code': 'CEP', 'home_phone': 'Tel. Residencial', 'pager': 'Pager', 'mobile': 'Celular', 'fax': 'Fax', 'title': 'Cargo', 'department': 'Departamento', 'company': 'Empresa'}
    available_views = {'can_view_user_stats': 'Estatísticas de Usuários', 'can_view_deactivated_last_7_days': 'Desativados (7 dias)', 'can_view_scheduled_deactivations': 'Desativações Agendadas', 'can_view_pending_reactivations': 'Reativações Agendadas', 'can_view_expiring_passwords': 'Senhas Expirando', 'can_export_data': 'Exportar Base AD'}

    search_form = GroupSearchForm()
    permissions_form = FlaskForm()
    groups = []

    try:
        conn = get_service_account_connection()
        search_base = load_config().get('AD_SEARCH_BASE')

        if search_form.validate_on_submit():
            query = search_form.search_query.data
            conn.search(search_base, f"(&(objectClass=group)(cn=*{query}*))", attributes=['cn'])
            groups = sorted([g.cn.value for g in conn.entries])
            if not groups: flash(f"Nenhum grupo encontrado com '{query}'.", "info")

        if request.method == 'POST' and 'save_permissions' in request.form:
            data = load_permissions()
            for group in request.form.getlist('searched_groups'):
                perm_type = request.form.get(f'{group}_perm_type')
                if perm_type == 'full': data[group] = {'type': 'full'}
                elif perm_type == 'custom':
                    data[group] = {
                        'type': 'custom',
                        'actions': {k: f'{group}_action_{k}' in request.form for k in ['can_create', 'can_disable', 'can_reset_password', 'can_edit', 'can_manage_groups']},
                        'views': {k: f'{group}_view_{k}' in request.form for k in available_views},
                        'fields': [k for k in available_fields if f'{group}_field_{k}' in request.form]
                    }
                else: data[group] = {'type': 'none'}

            # Módulo de salvamento de permissões aqui
            with open(PERMISSIONS_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)

            flash('Permissões salvas!', 'success')
            if 'search_query_hidden' in request.form and request.form['search_query_hidden']:
                 conn.search(search_base, f"(&(objectClass=group)(cn=*{request.form['search_query_hidden']}*))", attributes=['cn'])
                 groups = sorted([g.cn.value for g in conn.entries])

        return render_template('admin/permissions.html', search_form=search_form, permissions_form=permissions_form, groups=groups, permissions=load_permissions(), available_fields=available_fields, available_views=available_views)
    except Exception as e:
        flash(f"Erro na página de permissões: {e}", "error")
        logging.error(f"Erro em permissions: {e}", exc_info=True)
        return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)