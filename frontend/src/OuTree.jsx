import React, { useState, useEffect, useRef } from 'react';
import Tree from 'rc-tree';
import { useDrop } from 'react-dnd';
import 'rc-tree/assets/index.css';

const ItemTypes = {
  USER: 'user',
};

const TreeNodeTitle = ({ nodeData, onMoveUser, onHoverExpand }) => {
  // ... (código do TreeNodeTitle permanece o mesmo)
};

const OuTree = ({ onSelectOu, onUserMoved, foundUser }) => {
  const [treeData, setTreeData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedKeys, setExpandedKeys] = useState([]);
  const [selectedKeys, setSelectedKeys] = useState([]);

  // Função para encontrar todos os DNs pais de uma dada OU
  const getParentDns = (ouDn, allNodes) => {
    const parents = [];
    let currentDn = ouDn;
    let parentNode = allNodes.find(n => n.children?.some(c => c.key === currentDn));

    while (parentNode) {
      parents.push(parentNode.key);
      currentDn = parentNode.key;
      parentNode = allNodes.find(n => n.children?.some(c => c.key === currentDn));
    }
    return parents;
  };

  useEffect(() => {
    fetch('/api/ou_tree')
      .then(response => response.json())
      .then(data => {
        const flattenNodes = (nodes) => {
            let flat = [];
            nodes.forEach(node => {
                flat.push(node);
                if (node.children) {
                    flat = flat.concat(flattenNodes(node.children));
                }
            });
            return flat;
        };

        const adaptData = (nodes) => nodes.map(node => ({
          ...node,
          key: node.id,
          title: node.text,
          children: node.children ? adaptData(node.children) : [],
        }));

        const adaptedData = adaptData(data);
        setTreeData(adaptedData);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  // Efeito para lidar com a busca de usuário
  useEffect(() => {
    if (foundUser && treeData.length > 0) {
      const { ou_dn } = foundUser;

      const getAllNodes = (nodes) => {
          let list = [];
          nodes.forEach(node => {
              list.push(node);
              if (node.children) {
                  list = list.concat(getAllNodes(node.children));
              }
          });
          return list;
      };

      const allNodes = getAllNodes(treeData);
      const parentDns = getParentDns(ou_dn, allNodes);

      setExpandedKeys([...parentDns, ou_dn]);
      setSelectedKeys([ou_dn]);
    }
  }, [foundUser, treeData]);

  const handleMoveUser = (item, targetOuNode) => {
    // ... (lógica de mover usuário permanece a mesma)
  };

  const handleHoverExpand = (node) => {
    // ... (lógica de expansão ao arrastar permanece a mesma)
  };

  if (loading) return <p>Carregando...</p>;
  if (error) return <p style={{ color: 'red' }}>{error}</p>;

  const handleSelect = (keys, { node }) => {
    setSelectedKeys(keys);
    if (node) {
      onSelectOu({ id: node.key, text: node.title });
    }
  };

  const handleExpand = (keys) => {
    setExpandedKeys(keys);
  };

  const renderIcon = (props) => {
    // ... (lógica do ícone permanece a mesma)
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
      selectedKeys={selectedKeys}
      showLine
      icon={renderIcon}
      titleRender={titleRender}
    />
  );
};

export default OuTree;