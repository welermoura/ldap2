import React, { useState, useEffect } from 'react';
import UserItem from './UserItem';

const UserList = ({ selectedOu, ouPath, foundUser }) => {
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
      .then(response => response.json())
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
        <h5>Selecione uma OU ou busque por um usuário.</h5>
      </div>
    );
  }

  return (
    <div>
      <h5 className="mb-3">Usuários em: {ouPath || '...'}</h5>
      {loading && <p>Carregando usuários...</p>}
      {error && <p style={{ color: 'red' }}>{error}</p>}
      {!loading && !error && (
        users.length > 0 ? (
          users.map(user => {
            const isFound = foundUser && user.dn === foundUser.user_dn;
            return (
              <div key={user.dn} className={isFound ? 'found-user-highlight' : ''}>
                <UserItem user={user} />
              </div>
            );
          })
        ) : (
          <p className="text-muted">Nenhum usuário encontrado nesta OU.</p>
        )
      )}
    </div>
  );
};

export default UserList;