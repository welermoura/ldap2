import { useState } from 'react';
import OuTree from './OuTree';
import UserList from './UserList';
import './App.css';

function App() {
  const [selectedOu, setSelectedOu] = useState(null);
  // Adicionamos um estado para forçar a atualização dos componentes filhos
  const [refreshKey, setRefreshKey] = useState(0);

  const handleMoveUser = (draggedItem, targetOuNode) => {
    const userDn = draggedItem.userDn;
    const targetOuDn = targetOuNode.key;
    const userDisplayName = draggedItem.displayName;
    const targetOuName = targetOuNode.title;

    // Extrai a OU de origem do DN do usuário
    const originalOuDn = userDn.substring(userDn.indexOf(',') + 1);

    if (originalOuDn === targetOuDn) {
      alert('O usuário já está nesta Unidade Organizacional.');
      return;
    }

    if (window.confirm(`Tem certeza que deseja mover '${userDisplayName}' para a OU '${targetOuName}'?`)) {
      fetch('/api/move_user', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': window.csrf_token || ''
        },
        body: JSON.stringify({
          user_dn: userDn,
          target_ou_dn: targetOuDn,
        }),
      })
      .then(response => response.json().then(data => ({ ok: response.ok, body: data })))
      .then(({ ok, body }) => {
        if (ok) {
          alert(body.message || 'Usuário movido com sucesso!');
          // Força a recarga da lista de usuários atualizando a chave
          // Isso fará com que o UserList refaça o fetch dos dados
          setRefreshKey(oldKey => oldKey + 1);
        } else {
          throw new Error(body.error || 'Falha ao mover o usuário.');
        }
      })
      .catch(error => {
        console.error('Erro ao mover usuário:', error);
        alert(`Erro: ${error.message}`);
      });
    }
  };

  const handleSelectOu = (ou) => {
    setSelectedOu(ou);
  };

  return (
    <div className="ou-container">
      <div id="ou-tree-container">
        <OuTree onSelectOu={handleSelectOu} onUserMoved={handleMoveUser} />
      </div>
      <div id="user-list-container">
        {/* Passamos a chave de atualização para o UserList */}
        <UserList key={refreshKey} selectedOu={selectedOu} />
      </div>
    </div>
  );
}

export default App;