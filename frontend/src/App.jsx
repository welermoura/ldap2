import React, { useState, useEffect } from 'react';
import OuTree from './OuTree';
import UserList from './UserList';
import './App.css';

function App() {
  const [selectedOu, setSelectedOu] = useState(null);
  const [ouPath, setOuPath] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [isSearchMode, setIsSearchMode] = useState(false);

  const handleMoveUser = (draggedItem, targetOuNode) => {
    // ... (lógica de mover usuário permanece a mesma)
  };

  const handleSearch = (e) => {
    e.preventDefault();
    if (!searchTerm.trim()) {
      setIsSearchMode(false);
      setSearchResults([]);
      return;
    }

    fetch(`/api/search_user_location?q=${encodeURIComponent(searchTerm)}`)
      .then(response => response.json())
      .then(data => {
        if (data.error) {
          throw new Error(data.error);
        }
        setSearchResults(data);
        setIsSearchMode(true);
      })
      .catch(error => {
        alert(error.message || 'Erro ao buscar usuários.');
        setSearchResults([]);
      });
  };

  const handleSelectOu = (ou) => {
    setSelectedOu({ id: ou.id });
    setOuPath(ou.path);
    setIsSearchMode(false); // Sai do modo de busca ao selecionar uma OU
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
        </div>
      </div>

      <div className="ou-container">
        <div id="ou-tree-container">
          <OuTree
            onSelectOu={handleSelectOu}
            onUserMoved={handleMoveUser}
          />
        </div>
        <div id="user-list-container">
          <UserList
            key={refreshKey}
            selectedOu={selectedOu}
            ouPath={ouPath}
            searchResults={searchResults}
            isSearchMode={isSearchMode}
          />
        </div>
      </div>
    </>
  );
}

export default App;