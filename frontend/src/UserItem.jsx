import React from 'react';
import { useDrag } from 'react-dnd';

const ItemTypes = {
  USER: 'user',
};

const UserItem = ({ user, isSearchMode }) => {
  const [{ isDragging }, drag] = useDrag(() => ({
    type: ItemTypes.USER,
    item: { userDn: user.dn, displayName: user.displayName },
    collect: (monitor) => ({
      isDragging: !!monitor.isDragging(),
    }),
  }));

  const userDetailUrl = `/view_user/${user.sAMAccountName}`;
  const tooltipText = `Cargo: ${user.title || 'N/A'}\nDepartamento: ${user.department || 'N/A'}`;

  return (
    <a
      href={userDetailUrl}
      target="_blank"
      rel="noopener noreferrer"
      ref={drag}
      className="user-item-link"
      title={tooltipText}
      style={{
        opacity: isDragging ? 0.5 : 1,
      }}
    >
      <div className="user-item">
        <div className="user-info">
          <i className={`fas ${user.objectClass === 'computer' ? 'fa-desktop' : 'fa-user'} me-2`}></i>
          <div>
            <span className="user-name">{user.displayName}</span>
            <span className="user-login text-muted">{user.sAMAccountName}</span>
          </div>
        </div>
        <div className="user-details text-muted">
          {isSearchMode ? (
            <span className="ou-path">{user.ou_path}</span>
          ) : (
            <>
              <span>{user.title || 'Sem cargo'}</span>
              <span>{user.department || 'Sem depto.'}</span>
            </>
          )}
        </div>
      </div>
    </a>
  );
};

export default UserItem;