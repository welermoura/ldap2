import React, { useState, useEffect } from 'react';
import { DndProvider } from 'react-dnd';
import { HTML5Backend } from 'react-dnd-html5-backend';
import UserItem from './UserItem';

const UserList = ({ selectedOu, ouPath }) => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (selectedOu?.id) {
      setLoading(true);
      setError(null);
      fetch(`/api/ou_users?ou_dn=${encodeURIComponent(selectedOu.id)}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`Falha ao carregar usuários (status: ${response.status}).`);
            }
            const contentType = response.headers.get("content-type");
            if (contentType && contentType.indexOf("application/json") !== -1) {
                return response.json();
            } else {
                throw new Error("A resposta do servidor para a lista de usuários não é um JSON válido.");
            }
        })
        .then(data => {
          if (!Array.isArray(data)) {
            throw new Error(data.error || 'A resposta da API de usuários não é um formato de array válido.');
          }
          setUsers(data);
        })
        .catch(err => {
          setError(err.message);
          setUsers([]); // Limpa usuários em caso de erro
        })
        .finally(() => setLoading(false));
    } else {
      setUsers([]); // Limpa a lista se nenhuma OU for selecionada
      setError(null);
    }
  }, [selectedOu]);

  return (
    <DndProvider backend={HTML5Backend}>
      <div className="user-list-header">
        <h5 className="mb-0 text-truncate" title={ouPath}>
            {ouPath || 'Conteúdo da OU'}
        </h5>
        <span className="badge bg-dark ms-2">{users.length}</span>
      </div>
      <div className="user-list-body">
        {loading && <div className="p-3 text-center">Carregando usuários...</div>}
        {error && <div className="p-3 text-center text-danger">{error}</div>}
        {!loading && !error && !selectedOu && (
          <div className="p-3 text-center text-muted">
            <i className="fas fa-arrow-left me-2"></i> Selecione uma OU para ver seu conteúdo.
          </div>
        )}
        {!loading && !error && selectedOu && users.length === 0 && (
          <div className="p-3 text-center text-muted">Esta OU está vazia.</div>
        )}
        {!loading && !error && users.length > 0 && (
          <div className="list-group list-group-flush">
            {users.map(user => (
              <UserItem key={user.id} user={user} parentOuId={selectedOu.id} />
            ))}
          </div>
        )}
      </div>
    </DndProvider>
  );
};

export default UserList;