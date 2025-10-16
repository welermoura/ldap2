import React from 'react';
import { useDrag } from 'react-dnd';

// Definimos um tipo para o nosso item arrastável
const ItemTypes = {
  USER: 'user',
};

const UserItem = ({ user }) => {
  const [{ isDragging }, drag] = useDrag(() => ({
    type: ItemTypes.USER,
    // 'item' é a informação que será passada para o alvo quando soltar
    item: { userDn: user.dn, displayName: user.displayName },
    collect: (monitor) => ({
      isDragging: !!monitor.isDragging(),
    }),
  }));

  return (
    <div
      ref={drag} // Anexamos a referência de arrastar ao nosso elemento
      className="user-item"
      style={{
        opacity: isDragging ? 0.5 : 1,
        cursor: 'move',
      }}
    >
      <span>
        <i className="fas fa-user me-2"></i>
        {user.displayName}
      </span>
      <small className="text-muted">{user.sAMAccountName}</small>
    </div>
  );
};

export default UserItem;