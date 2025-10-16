import React, { useState, useEffect } from 'react';
import UserItem from './UserItem';

const UserList = ({ selectedOu }) => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!selectedOu) {
      setUsers([]);
      return;
    }

    setLoading(true);
    setError(null);
    fetch(`/api/ou_users/${encodeURIComponent(selectedOu.id)}`)
      .then(response => {
        if (!response.ok) {
          throw new Error('Falha ao buscar usuários');
        }
        return response.json();
      })
      .then(data => {
        setUsers(data);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, [selectedOu]);

  if (!selectedOu) {
    return (
      <div className="text-center text-muted p-5">
        <h5>Selecione uma OU na árvore para ver os usuários.</h5>
        <p>Você poderá arrastar usuários desta lista para uma nova OU na árvore.</p>
      </div>
    );
  }

  return (
    <div>
      <h5 className="mb-3">Usuários em: {selectedOu.text}</h5>
      {loading && <p>Carregando usuários...</p>}
      {error && <p style={{ color: 'red' }}>{error}</p>}
      {!loading && !error && (
        users.length > 0 ? (
          users.map(user => <UserItem key={user.dn} user={user} />)
        ) : (
          <p className="text-muted">Nenhum usuário encontrado nesta OU.</p>
        )
      )}
    </div>
  );
};

export default UserList;