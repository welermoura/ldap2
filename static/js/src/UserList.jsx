import React from 'react';
import { useDrag } from 'react-dnd';

// Definimos um tipo de item para o DND. Isso ajuda a garantir
// que apenas fontes de arraste compatíveis possam ser soltas em alvos de soltura.
const ItemTypes = {
    USER: 'user'
};

const UserItem = ({ user }) => {
    // O hook useDrag nos dá tudo o que precisamos para tornar este componente arrastável.
    const [{ isDragging }, drag] = useDrag(() => ({
        type: ItemTypes.USER,
        // 'item' é o objeto de dados que será passado quando o item for solto.
        item: { id: user.id, name: user.text },
        // 'collect' monitora o estado do arraste.
        collect: (monitor) => ({
            isDragging: !!monitor.isDragging(),
        }),
    }));

    return (
        // Anexamos a ref 'drag' ao nosso elemento para torná-lo arrastável.
        <div ref={drag} className="list-group-item" style={{
                cursor: 'grab',
                opacity: isDragging ? 0.5 : 1, // Dá um feedback visual durante o arraste
            }}>
            <i className="fas fa-user me-2"></i>
            <strong>{user.text}</strong>
            <small className="text-muted d-block">{user.title || 'Cargo não definido'}</small>
        </div>
    );
};

const UserList = ({ users, selectedOUName }) => {
    if (!selectedOUName) {
        return (
            <div className="text-center text-muted p-5">
                <i className="fas fa-arrow-left fa-3x mb-3"></i>
                <h5>Selecione uma OU na árvore para ver os usuários.</h5>
            </div>
        );
    }

    if (users.length === 0) {
        return (
             <div className="text-center text-muted p-5">
                <i className="fas fa-info-circle fa-3x mb-3"></i>
                <h5>Nenhum usuário encontrado nesta OU.</h5>
            </div>
        );
    }

    return (
        <div className="list-group">
            {users.map(user => (
                <UserItem key={user.id} user={user} />
            ))}
        </div>
    );
};

export default UserList;
export { ItemTypes }; // Exportamos para que o alvo de soltura possa usá-lo