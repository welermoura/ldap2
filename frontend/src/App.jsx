import { useState } from 'react';
import OuTree from './OuTree';
import UserList from './UserList';
import './App.css';

function App() {
  const [selectedOu, setSelectedOu] = useState(null);
  const [ouPath, setOuPath] = useState(''); // Novo estado para o caminho da OU
  const [refreshKey, setRefreshKey] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [foundUser, setFoundUser] = useState(null);

  const handleMoveUser = (draggedItem, targetOuNode) => {
    // ... (lógica de mover usuário permanece a mesma)
  };

  const handleSearch = (e) => {
    e.preventDefault();
    if (!searchTerm.trim()) return;

    fetch(`/api/search_user_location?q=${encodeURIComponent(searchTerm)}`)
      .then(response => response.json())
      .then(data => {
        setFoundUser(data);
        setSelectedOu({ id: data.ou_dn });
      })
      .catch(error => {
        alert('Usuário não encontrado.');
        setFoundUser(null);
      });
  };

  const handleSelectOu = (ou) => {
    setSelectedOu({ id: ou.id });
    setOuPath(ou.path); // Armazena o caminho completo
    setFoundUser(null);
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
            ouPath={ouPath} // Passa o caminho para a lista de usuários
            foundUser={foundUser}
          />
        </div>
      </div>
    </>
  );
}

export default App;