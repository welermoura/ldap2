import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { DndProvider } from 'react-dnd';
import { HTML5Backend } from 'react-dnd-html5-backend';

import ReactTreeView from './ReactTreeView.jsx';
import UserList from './UserList.jsx';
import SearchUser from './SearchUser.jsx';

// Pega o token CSRF do meta tag
const getCsrfToken = () => {
    const tokenTag = document.querySelector('meta[name="csrf-token"]');
    return tokenTag ? tokenTag.getAttribute('content') : '';
};

const OUManagement = () => {
    const [ouTree, setOuTree] = useState([]);
    const [selectedOU, setSelectedOU] = useState({ dn: null, name: null });
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [loadingUsers, setLoadingUsers] = useState(false);
    const [alert, setAlert] = useState({ show: false, message: '', type: 'info' });
    const [ouTreeRef, setOuTreeRef] = useState(null); // Ref para o componente da árvore

    const showAlert = (message, type = 'info', duration = 5000) => {
        setAlert({ show: true, message, type });
        setTimeout(() => setAlert({ show: false, message: '', type: 'info' }), duration);
    };

    useEffect(() => {
        axios.get('/api/ou_tree')
            .then(response => {
                setOuTree(response.data);
                setLoading(false);
            })
            .catch(err => {
                console.error("Erro ao buscar a árvore de OUs:", err);
                showAlert("Não foi possível carregar a estrutura de OUs.", "danger");
                setLoading(false);
            });
    }, []);

    const fetchUsers = useCallback((ou_dn, ou_name) => {
        if (!ou_dn) return;
        setSelectedOU({ dn: ou_dn, name: ou_name });
        setLoadingUsers(true);
        setUsers([]);

        axios.get(`/api/ou_users/${encodeURIComponent(ou_dn)}`)
            .then(response => {
                setUsers(response.data);
                setLoadingUsers(false);
            })
            .catch(err => {
                console.error(`Erro ao buscar usuários para ${ou_dn}:`, err);
                showAlert(`Não foi possível carregar os usuários para ${ou_name}.`, "danger");
                setLoadingUsers(false);
            });
    }, []);

    const handleMoveUser = useCallback((user_sam, target_ou_dn) => {
        const csrfToken = getCsrfToken();
        axios.post('/api/move_user', {
            user_sam: user_sam,
            target_ou_dn: target_ou_dn
        }, {
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken }
        })
        .then(response => {
            if (response.data.success) {
                showAlert(response.data.message, 'success');
                setUsers(prevUsers => prevUsers.filter(user => user.id !== user_sam));
            } else {
                showAlert(response.data.error || 'Ocorreu um erro desconhecido.', 'danger');
            }
        })
        .catch(err => {
            console.error("Erro ao mover usuário:", err);
            showAlert('Erro de comunicação ao tentar mover o usuário.', 'danger');
        });
    }, []);

    const handleSearchUser = (query) => {
        const csrfToken = getCsrfToken();
        return axios.post('/api/search_user_location', { query }, {
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken }
        });
    };

    const handleSearchResult = (data) => {
        if (ouTreeRef) {
            ouTreeRef.navigateToOU(data.ou_dn);
        }
    };

    if (loading) {
        return <div className="text-center p-5"><div className="spinner-border text-primary" role="status"><span className="visually-hidden">Carregando...</span></div></div>;
    }

    return (
        <DndProvider backend={HTML5Backend}>
            {alert.show && (
                 <div className={`alert alert-${alert.type} alert-dismissible fade show`} role="alert">
                    <i className="fas fa-info-circle me-2"></i>{alert.message}
                    <button type="button" className="btn-close" onClick={() => setAlert({ show: false })} aria-label="Close"></button>
                </div>
            )}
            <div className="row">
                <div className="col-md-5">
                    <SearchUser onSearch={handleSearchUser} onResult={handleSearchResult} showAlert={showAlert} />
                    <div className="card glass-card mt-4">
                        <div className="card-header">
                            <h5 className="mb-0"><i className="fas fa-sitemap me-2"></i>Estrutura do Active Directory</h5>
                        </div>
                        <div className="card-body tree-container">
                            <ReactTreeView
                                treeData={ouTree}
                                onSelectOU={fetchUsers}
                                onMoveUser={handleMoveUser}
                                ref={setOuTreeRef}
                            />
                        </div>
                    </div>
                </div>
                <div className="col-md-7">
                    <div className="card glass-card">
                         <div className="card-header">
                            <h5 className="mb-0">
                                <i className="fas fa-users me-2"></i>
                                Usuários em <strong>{selectedOU.name || 'Nenhuma'}</strong>
                            </h5>
                        </div>
                        <div className="card-body tree-container">
                            {loadingUsers ? (
                                 <div className="text-center p-5"><div className="spinner-border text-primary" role="status"></div></div>
                            ) : (
                                <UserList users={users} selectedOUName={selectedOU.name} />
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </DndProvider>
    );
};

export default OUManagement;