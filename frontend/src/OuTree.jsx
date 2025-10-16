import React, { useState, useEffect } from 'react';
import Tree from 'rc-tree';
import { useDrop } from 'react-dnd';
import 'rc-tree/assets/index.css';

// O tipo de item que o nosso alvo de soltura aceitará
const ItemTypes = {
  USER: 'user',
};

// Componente customizado para o título do nó, que atuará como alvo de soltura
const TreeNodeTitle = ({ nodeData, onMoveUser }) => {
  const [{ isOver, canDrop }, drop] = useDrop(() => ({
    accept: ItemTypes.USER,
    drop: (item) => onMoveUser(item, nodeData), // Função chamada ao soltar
    collect: (monitor) => ({
      isOver: !!monitor.isOver(),
      canDrop: !!monitor.canDrop(),
    }),
  }));

  return (
    <div ref={drop} style={{
      padding: '2px 5px',
      backgroundColor: isOver && canDrop ? '#e6f7ff' : 'transparent',
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
    // A lógica da chamada da API será adicionada no App.jsx para centralizar o estado
    console.log(`Mover usuário ${item.userDn} para OU ${targetOuNode.key}`);
    // A função onUserMoved será passada do App.jsx
    if (onUserMoved) {
        onUserMoved(item, targetOuNode);
    }
  };

  if (loading) return <p>Carregando...</p>;
  if (error) return <p style={{ color: 'red' }}>{error}</p>;

  const handleSelect = (selectedKeys, { node }) => {
    if (node) {
      onSelectOu({ id: node.key, text: node.title });
    }
  };

  // Usamos titleRender para injetar nosso componente de drop target
  const titleRender = (nodeData) => (
    <TreeNodeTitle nodeData={nodeData} onMoveUser={handleMoveUser} />
  );

  return (
    <Tree
      treeData={treeData}
      onSelect={handleSelect}
      defaultExpandAll
      showLine
      titleRender={titleRender}
    />
  );
};

export default OuTree;