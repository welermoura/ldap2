import React, { useState, useEffect, useRef } from 'react';
import Tree from 'rc-tree';
import { useDrop } from 'react-dnd';
import 'rc-tree/assets/index.css';

// O tipo de item que o nosso alvo de soltura aceitará
const ItemTypes = {
  USER: 'user',
};

// Componente customizado para o título do nó, que atuará como alvo de soltura
const TreeNodeTitle = ({ nodeData, onMoveUser, onHoverExpand }) => {
  const timerRef = useRef(null);

  const [{ isOver, canDrop }, drop] = useDrop(() => ({
    accept: ItemTypes.USER,
    drop: (item) => onMoveUser(item, nodeData),
    hover: (item, monitor) => {
      // Se o mouse está sobre o nó e ele não está expandido
      if (monitor.isOver({ shallow: true })) {
        // Inicia o temporizador se ele não estiver rodando
        if (!timerRef.current) {
          timerRef.current = setTimeout(() => {
            onHoverExpand(nodeData);
            timerRef.current = null;
          }, 700); // Atraso de 700ms para expandir
        }
      }
    },
    collect: (monitor) => ({
      isOver: !!monitor.isOver({ shallow: true }),
      canDrop: !!monitor.canDrop(),
    }),
  }));

  // Limpa o temporizador se o mouse sair do nó
  useEffect(() => {
    if (!isOver && timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOver]);


  return (
    <div ref={drop} style={{
      padding: '2px 5px',
      backgroundColor: isOver && canDrop ? 'rgba(24, 144, 255, 0.2)' : 'transparent',
      border: isOver && canDrop ? '1px dashed #1890ff' : '1px dashed transparent',
      borderRadius: '2px',
    }}>
      {nodeData.title}
    </div>
  );
};


const OuTree = ({ onSelectOu, onUserMoved }) => {
  const [treeData, setTreeData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedKeys, setExpandedKeys] = useState([]);

  useEffect(() => {
    fetch('/api/ou_tree')
      .then(response => response.json())
      .then(data => {
        const adaptData = (nodes) => nodes.map(node => ({
          ...node,
          key: node.id,
          title: node.text,
          children: node.children ? adaptData(node.children) : [],
        }));
        setTreeData(adaptData(data));
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  const handleMoveUser = (item, targetOuNode) => {
    if (onUserMoved) {
        onUserMoved(item, targetOuNode);
    }
  };

  const handleHoverExpand = (node) => {
    // Adiciona a chave do nó à lista de nós expandidos, se já não estiver lá
    if (!expandedKeys.includes(node.key)) {
      setExpandedKeys(prevKeys => [...prevKeys, node.key]);
    }
  };

  if (loading) return <p>Carregando...</p>;
  if (error) return <p style={{ color: 'red' }}>{error}</p>;

  const handleSelect = (selectedKeys, { node }) => {
    if (node) {
      onSelectOu({ id: node.key, text: node.title });
    }
  };

  const handleExpand = (keys) => {
    setExpandedKeys(keys);
  };

  const renderIcon = (props) => {
    const iconClass = props.isLeaf ? 'fas fa-folder' : (props.expanded ? 'fas fa-folder-open' : 'fas fa-folder');
    return <i className={`${iconClass} me-2`} style={{ color: '#f1c40f' }}></i>;
  };

  const titleRender = (nodeData) => (
    <TreeNodeTitle nodeData={nodeData} onMoveUser={handleMoveUser} onHoverExpand={handleHoverExpand} />
  );

  return (
    <Tree
      treeData={treeData}
      onSelect={handleSelect}
      onExpand={handleExpand}
      expandedKeys={expandedKeys}
      showLine
      icon={renderIcon}
      titleRender={titleRender}
    />
  );
};

export default OuTree;