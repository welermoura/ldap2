import { useState } from 'react';
import OuTree from './OuTree';
import UserList from './UserList';
import './App.css';

function App() {
  const [selectedOu, setSelectedOu] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [foundUser, setFoundUser] = useState(null); // Para destacar o usuário encontrado

  const handleMoveUser = (draggedItem, targetOuNode) => {
    // ... (lógica de mover usuário permanece a mesma)
  };

  const handleSearch = (e) => {
    e.preventDefault();
    if (!searchTerm.trim()) return;

    fetch(`/api/search_user_location?q=${encodeURIComponent(searchTerm)}`)
      .then(response => {
        if (!response.ok) {
          return response.json().then(err => { throw new Error(err.error || 'Usuário não encontrado'); });
        }
        return response.json();
      })
      .then(data => {
        // Passa os dados do usuário encontrado para os componentes filhos
        setFoundUser(data);
        // Seleciona a OU do usuário encontrado para carregar a lista
        setSelectedOu({ id: data.ou_dn, text: '' }); // O texto será preenchido pela árvore
      })
      .catch(error => {
        alert(error.message);
        setFoundUser(null);
      });
  };

  const handleSelectOu = (ou) => {
    setSelectedOu(ou);
    setFoundUser(null); // Limpa a busca ao selecionar uma OU manualmente
  };

  return (
    <>
      <div className="card glass-card mb-4">
        <div className="card-body">
          <form onSubmit={handleSearch} className="d-flex gap-2">
            <input
              type="text"
              className="form-control"
              placeholder="Buscar usuário por nome ou login..."
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
            foundUser={foundUser}
          />
        </div>
        <div id="user-list-container">
          <UserList
            key={refreshKey}
            selectedOu={selectedOu}
            foundUser={foundUser}
          />
        </div>
      </div>
    </>
  );
}

export default App;