import React from 'react';
import { useDrag } from 'react-dnd';

const ItemTypes = {
  USER: 'user',
};

const UserItem = ({ user, parentOuId }) => {
  const [{ isDragging }, drag] = useDrag(() => ({
    type: ItemTypes.USER,
    // Os dados que serão passados quando o item for arrastado
    item: { id: user.id, parentOuId: parentOuId },
    collect: (monitor) => ({
      isDragging: !!monitor.isDragging(),
    }),
  }));

  const getIcon = () => {
    const iconClass = user.type === 'computer' ? 'fa-desktop' : 'fa-user';
    const colorClass = user.disabled ? 'text-warning' : 'text-primary';
    return <i className={`fas ${iconClass} me-3 ${colorClass}`}></i>;
  };

  return (
    <div
      ref={drag}
      className="list-group-item list-group-item-action user-item"
      style={{
        opacity: isDragging ? 0.5 : 1,
        cursor: 'move',
      }}
    >
      <div className="d-flex w-100 align-items-center">
        {getIcon()}
        <div className="flex-grow-1">
          <h6 className="mb-0">{user.name}</h6>
          {user.sam && <small className="text-muted">{user.sam}</small>}
        </div>
        {user.disabled && (
            <span className="badge bg-warning text-dark">Desativado</span>
        )}
      </div>
    </div>
  );
};

export default UserItem;