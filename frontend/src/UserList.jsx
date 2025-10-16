import React, { useState, useEffect } from 'react';
import UserItem from './UserItem';

const UserList = ({ selectedOu, ouPath, searchResults, isSearchMode }) => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Se não estiver em modo de busca e uma OU for selecionada, busca os usuários da OU
    if (!isSearchMode && selectedOu) {
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
    } else {
      // Se estiver em modo de busca ou nenhuma OU selecionada, limpa a lista
      setUsers([]);
    }
  }, [selectedOu, isSearchMode]);

  const itemsToDisplay = isSearchMode ? searchResults : users;
  const title = isSearchMode ? `Resultados da Busca: ${searchResults.length} encontrado(s)` : `Objetos em: ${ouPath || '...'}`;

  if (!isSearchMode && !selectedOu) {
    return (
      <div className="text-center text-muted p-5">
        <h5>Selecione uma OU ou busque por um objeto.</h5>
      </div>
    );
  }

  return (
    <div>
      <h5 className="mb-3">{title}</h5>
      {loading && <p>Carregando...</p>}
      {error && <p style={{ color: 'red' }}>{error}</p>}
      {!loading && !error && (
        itemsToDisplay.length > 0 ? (
          itemsToDisplay.map(item => (
            <UserItem key={item.dn} user={item} isSearchMode={isSearchMode} />
          ))
        ) : (
          <p className="text-muted">Nenhum objeto encontrado.</p>
        )
      )}
    </div>
  );
};

export default UserList;