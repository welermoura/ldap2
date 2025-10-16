import React, { useState, useCallback } from 'react';
import OuTree from './OuTree';
import UserList from './UserList';
import './App.css';

function App() {
  const [selectedOu, setSelectedOu] = useState(null);
  const [ouPath, setOuPath] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [foundObject, setFoundObject] = useState(null);
  const [searchMessage, setSearchMessage] = useState('');

  const handleSelectOu = useCallback((ou) => {
    setSelectedOu({ id: ou.id });
    setOuPath(ou.path);
    setFoundObject(null); // Limpa o objeto encontrado ao selecionar uma OU
  }, []);

  const handleUserMoved = useCallback(() => {
    // Incrementa a chave para forçar a remontagem e atualização do UserList
    setRefreshKey(prevKey => prevKey + 1);
    // Também poderia recarregar a árvore, se necessário
  }, []);

  const handleSearch = (e) => {
    e.preventDefault();
    if (!searchTerm.trim()) {
        setFoundObject(null);
        setSearchMessage('');
        return;
    }

    setSearchMessage('Buscando...');
    fetch(`/api/search_user_location?q=${encodeURIComponent(searchTerm)}`)
      .then(response => {
        if (!response.ok) {
          return response.json().then(err => { throw new Error(err.error || 'Erro de rede') });
        }
        return response.json();
      })
      .then(data => {
        setFoundObject(data);
        setSearchMessage(''); // Limpa a mensagem em caso de sucesso
      })
      .catch(error => {
        console.error('Search error:', error);
        setFoundObject(null);
        setSearchMessage(error.message || 'Erro ao buscar objeto.');
      });
  };

  return (
    <>
      <div className="card glass-card mb-4">
        <div className="card-body">
          <form onSubmit={handleSearch} className="d-flex gap-2">
            <input
              type="text"
              className="form-control"
              placeholder="Buscar usuário ou computador por nome/login..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
            <button type="submit" className="btn btn-primary">
              <i className="fas fa-search"></i>
            </button>
          </form>
          {searchMessage && <p className="mt-2 text-info">{searchMessage}</p>}
        </div>
      </div>

      <div className="ou-container">
        <div id="ou-tree-container" className="glass-card">
          <OuTree
            onSelectOu={handleSelectOu}
            onUserMoved={handleUserMoved}
            foundObject={foundObject}
          />
        </div>
        <div id="user-list-container" className="glass-card">
          <UserList
            key={refreshKey}
            selectedOu={selectedOu}
            ouPath={ouPath}
          />
        </div>
      </div>
    </>
  );
}

export default App;