import os
import logging
from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify, Response
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, ValidationError, Length, EqualTo
import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE, BASE, LEVEL
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
import base64

# ... (código inicial sem alterações) ...

def get_ou_path_for_dn(conn, dn):
    """
    Busca o caminho hierárquico de uma OU a partir de um DN.
    Ex: "Produção > Servidores"
    """
    path_parts = []
    current_dn = dn
    while True:
        try:
            conn.search(current_dn, '(objectClass=*)', BASE, attributes=['ou', 'cn'])
            if not conn.entries:
                break
            entry = conn.entries[0]
            # O nome pode ser 'ou' ou 'cn' para contêineres
            name = get_attr_value(entry, 'ou') or get_attr_value(entry, 'cn')
            if name:
                path_parts.append(name)

            parent_dn = get_ou_from_dn(current_dn)
            if parent_dn == current_dn or not parent_dn: # Chegou na raiz
                break
            current_dn = parent_dn
        except ldap3.core.exceptions.LDAPNoSuchObjectResult:
            break
    return ' > '.join(reversed(path_parts))


@app.route('/api/ou_tree')
@require_auth
@require_permission(action='can_move_users')
def api_ou_tree():
    try:
        conn = get_read_connection()
        config = load_config()
        search_base = config.get('AD_SEARCH_BASE')

        conn.search(
            search_base,
            '(objectClass=organizationalUnit)',
            SUBTREE,
            attributes=['ou', 'distinguishedName']
        )

        all_ous = {
            entry.entry_dn: {
                'id': entry.entry_dn,
                'text': get_attr_value(entry, 'ou'),
                'parent': get_ou_from_dn(entry.entry_dn),
                'children': []
            }
            for entry in conn.entries
        }

        tree = []
        for dn, ou_node in all_ous.items():
            parent_dn = ou_node['parent']
            if parent_dn in all_ous:
                all_ous[parent_dn]['children'].append(ou_node)
            elif parent_dn == search_base:
                tree.append(ou_node)

        for ou_node in all_ous.values():
            ou_node['children'].sort(key=lambda x: x['text'])
        tree.sort(key=lambda x: x['text'])

        return jsonify(tree)

    except Exception as e:
        logging.error(f"Erro na API da árvore de OUs: {e}", exc_info=True)
        return jsonify({'error': 'Falha ao carregar a árvore de OUs.'}), 500

# ... (código de /api/ou_users/ sem alterações) ...

@app.route('/api/move_user', methods=['POST'])
@require_auth
@require_permission(action='can_move_users')
def api_move_user():
    data = request.get_json()
    user_dn = data.get('user_dn')
    target_ou_dn = data.get('target_ou_dn')

    if not user_dn or not target_ou_dn:
        return jsonify({'error': 'DN do usuário e DN da OU de destino são obrigatórios.'}), 400

    try:
        conn = get_service_account_connection()
        user_cn = user_dn.split(',')[0]
        conn.modify_dn(user_dn, user_cn, new_superior=target_ou_dn)

        if conn.result['result'] == 0:
            new_user_dn = f"{user_cn},{target_ou_dn}"
            log_message = (
                f"Usuário movido com sucesso por '{session.get('user_display_name')}'. "
                f"DN do Usuário: '{user_dn}', "
                f"Nova OU: '{target_ou_dn}'."
            )
            logging.info(log_message)
            return jsonify({'success': True, 'message': 'Usuário movido com sucesso!', 'new_dn': new_user_dn})
        else:
            error_message = conn.result.get('message', 'Erro desconhecido do servidor LDAP.')
            raise Exception(error_message)

    except Exception as e:
        # ... (tratamento de exceções) ...
        return jsonify({'error': f'Falha ao mover o usuário: {e}'}), 500


@app.route('/api/search_user_location')
@require_auth
@require_permission(action='can_move_users')
def api_search_user_location():
    search_term = request.args.get('q', '').strip()
    if not search_term:
        return jsonify([])

    try:
        conn = get_read_connection()
        # Busca por usuários e computadores
        search_filter = f"(&(objectCategory=person)(|(displayName=*{search_term}*)(sAMAccountName=*{search_term}*)))"
        conn.search(
            config.get('AD_SEARCH_BASE'),
            search_filter,
            SUBTREE,
            attributes=['displayName', 'sAMAccountName', 'title', 'department', 'objectClass', 'distinguishedName']
        )

        results = []
        for entry in conn.entries:
            ou_dn = get_ou_from_dn(entry.entry_dn)
            results.append({
                'displayName': get_attr_value(entry, 'displayName'),
                'sAMAccountName': get_attr_value(entry, 'sAMAccountName'),
                'dn': entry.entry_dn,
                'title': get_attr_value(entry, 'title'),
                'department': get_attr_value(entry, 'department'),
                'objectClass': 'computer' if 'computer' in entry.objectClass else 'user',
                'ou_path': get_ou_path_for_dn(conn, ou_dn)
            })

        return jsonify(results)

    except Exception as e:
        logging.error(f"Erro na API de busca de localização de usuário para o termo '{search_term}': {e}", exc_info=True)
        return jsonify({'error': 'Falha ao buscar a localização do usuário.'}), 500

# ... (resto do código sem alterações) ...