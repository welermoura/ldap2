import os
import logging
from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify, Response
# ... (imports)

# ... (configuração inicial)

# --- Funções Auxiliares ---
# ... (funções auxiliares)

# --- Rotas ---

@app.route('/dashboard')
@require_auth
def dashboard():
    context = {
        'active_users': 0,
        'disabled_users': 0,
        'deactivated_last_week': 0,
        'pending_reactivations': 0,
        'pending_deactivations': 0,
        'expiring_passwords': []
    }
    try:
        conn = get_read_connection()
        if check_permission(view='can_view_user_stats'):
            stats = get_dashboard_stats(conn)
            context['active_users'] = stats.get('enabled_users', 0)
            context['disabled_users'] = stats.get('disabled_users', 0)
        # ... (outras chamadas do dashboard)
    except Exception as e:
        logging.error(f"Erro ao carregar dados do dashboard: {e}", exc_info=True)
        flash(f"Erro ao carregar dados do dashboard. Verifique os logs.", "error")
    return render_template('dashboard.html', **context)


@app.route('/api/ou_tree')
@require_auth
@require_permission(action='can_move_users')
def api_ou_tree():
    try:
        conn = get_read_connection()
        # ... (código da função)
        return jsonify(tree)
    except Exception as e:
        logging.error(f"Erro fatal na API da árvore de OUs: {e}", exc_info=True)
        return jsonify({'error': 'Falha grave ao carregar a árvore de OUs. Verifique os logs.'}), 500


@app.route('/api/ou_users/<path:ou_dn>')
@require_auth
@require_permission(action='can_move_users')
def api_ou_users(ou_dn):
    try:
        conn = get_read_connection()
        # ... (código da função)
        return jsonify(users)
    except Exception as e:
        logging.error(f"Erro fatal na API de usuários da OU '{ou_dn}': {e}", exc_info=True)
        return jsonify({'error': f'Falha grave ao carregar usuários para a OU. Verifique os logs.'}), 500


@app.route('/api/move_user', methods=['POST'])
@require_auth
@require_permission(action='can_move_users')
def api_move_user():
    try:
        # ... (código da função)
        return jsonify({'success': True, 'message': 'Usuário movido com sucesso!', 'new_dn': new_user_dn})
    except Exception as e:
        logging.error(f"Erro fatal ao mover usuário: {e}", exc_info=True)
        return jsonify({'error': f'Falha grave ao mover o usuário. Verifique os logs.'}), 500


@app.route('/api/search_user_location')
@require_auth
@require_permission(action='can_move_users')
def api_search_user_location():
    try:
        # ... (código da função)
        return jsonify(results)
    except Exception as e:
        logging.error(f"Erro fatal na API de busca de localização de usuário: {e}", exc_info=True)
        return jsonify({'error': 'Falha grave ao buscar a localização do usuário. Verifique os logs.'}), 500

# ... (resto do código)