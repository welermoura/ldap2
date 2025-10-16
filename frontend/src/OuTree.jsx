import React, { useState, useEffect, useRef, useCallback } from 'react';
import Tree, { TreeNode } from 'rc-tree';
import { useDrop } from 'react-dnd';
import 'rc-tree/assets/index.css';
import './OuTree.css'; // Estilos customizados

const ItemTypes = {
  USER: 'user',
};

const CustomTreeNode = ({ nodeData, onMoveUser, onHoverExpand, isExpanded, isSelected }) => {
    const timerRef = useRef(null);

    const [{ isOver, canDrop }, drop] = useDrop(() => ({
      accept: ItemTypes.USER,
      drop: (item) => onMoveUser(item, nodeData),
      hover: (item, monitor) => {
        if (monitor.isOver({ shallow: true }) && !isExpanded) {
          if (!timerRef.current) {
            timerRef.current = setTimeout(() => {
              onHoverExpand(nodeData);
              timerRef.current = null;
            }, 700); // Atraso para expandir
          }
        }
      },
      collect: (monitor) => ({
        isOver: !!monitor.isOver({ shallow: true }),
        canDrop: !!monitor.canDrop(),
      }),
    }));

    useEffect(() => {
      // Limpa o timer se o mouse sair do nó
      if (!isOver && timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    }, [isOver]);

    // Define a classe do título para estilização
    const titleClassName = `tree-node-title-wrapper ${isOver && canDrop ? 'drop-target-hover' : ''} ${isSelected ? 'selected-node' : ''}`;

    return (
      <div ref={drop} className={titleClassName}>
        {nodeData.title}
      </div>
    );
};

// Função para encontrar o caminho de um nó (breadcrumb)
const getPathForNode = (key, nodes) => {
    const path = [];
    let currentNode = nodes.find(n => n.key === key);
    while (currentNode) {
      path.unshift(currentNode.title);
      // Encontra o pai do nó atual
      const parent = nodes.find(p => p.children?.some(child => child.key === currentNode.key));
      currentNode = parent;
    }
    return path.join(' > ');
};

// Função para obter todos os nós em uma lista plana
const flattenTree = (nodes) => {
    let list = [];
    nodes.forEach(node => {
        list.push(node);
        if (node.children) {
            list = list.concat(flattenTree(node.children));
        }
    });
    return list;
};

// Função para obter os DNs pais de um nó
const getParentDns = (ouDn, allNodes) => {
    const parents = [];
    let currentNodeKey = ouDn;
    let parentNode;
    do {
      parentNode = allNodes.find(n => n.children?.some(c => c.key === currentNodeKey));
      if (parentNode) {
        parents.push(parentNode.key);
        currentNodeKey = parentNode.key;
      }
    } while (parentNode);
    return parents;
};


const OuTree = ({ onSelectOu, onUserMoved, foundObject }) => {
  const [treeData, setTreeData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedKeys, setExpandedKeys] = useState([]);
  const [selectedKeys, setSelectedKeys] = useState([]);
  const [allNodes, setAllNodes] = useState([]);

  useEffect(() => {
    fetch('/api/ou_tree')
      .then(response => {
        if (!response.ok) {
            throw new Error(`Falha ao carregar a estrutura de OUs (status: ${response.status}).`);
        }
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
            return response.json();
        } else {
            throw new Error("A resposta do servidor não é um JSON válido.");
        }
      })
      .then(data => {
        if (!Array.isArray(data)) {
            throw new Error(data.error || 'A resposta da API para a árvore de OUs não é um formato de array válido.');
        }

        const adaptData = (nodes) => nodes.map(node => ({
          ...node,
          key: node.id,
          title: node.text,
          children: node.children ? adaptData(node.children) : [],
        }));

        const adaptedData = adaptData(data);
        setTreeData(adaptedData);
        setAllNodes(flattenTree(adaptedData));

        // Expande o nó raiz por padrão
        if (adaptedData.length > 0) {
            setExpandedKeys([adaptedData[0].key]);
        }
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, [onUserMoved]); // Recarrega a árvore se um usuário for movido

  // Efeito para lidar com um objeto encontrado na busca
  useEffect(() => {
    if (foundObject && allNodes.length > 0) {
      const { ou_dn } = foundObject;
      const parentDns = getParentDns(ou_dn, allNodes);

      setExpandedKeys(prev => [...new Set([...prev, ...parentDns, ou_dn])]);
      setSelectedKeys([ou_dn]);

      const path = getPathForNode(ou_dn, allNodes);
      onSelectOu({ id: ou_dn, path: path });
    }
  }, [foundObject, allNodes, onSelectOu]);

  const handleMoveUser = (item, targetOuNode) => {
    if (item.parentOuId === targetOuNode.key) {
        console.log("Usuário já está na OU de destino.");
        return;
    }

    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || window.csrf_token;

    fetch('/api/move_user', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({
            object_dn: item.id,
            target_ou_dn: targetOuNode.key
        })
    })
    .then(response => response.json().then(data => ({ ok: response.ok, data })))
    .then(({ ok, data }) => {
        if (!ok) {
            throw new Error(data.error || 'Falha ao mover o usuário.');
        }
        alert(data.message || 'Usuário movido com sucesso!');
        if (onUserMoved) {
            onUserMoved();
        }
    })
    .catch(error => {
        console.error('Move error:', error);
        alert(`Erro: ${error.message}`);
    });
  };

  const handleHoverExpand = useCallback((node) => {
    if (!expandedKeys.includes(node.key)) {
      setExpandedKeys(prevKeys => [...prevKeys, node.key]);
    }
  }, [expandedKeys]);

  const handleSelect = (keys, { node }) => {
    setSelectedKeys(keys);
    if (keys.length > 0 && node) {
      const path = getPathForNode(node.key, allNodes);
      onSelectOu({ id: node.key, path: path });
    } else {
        onSelectOu(null); // Desseleciona se não houver nó
    }
  };

  const switcherIcon = (props) => {
    if (props.isLeaf) {
      return <span className="rc-tree-switcher-icon-leaf-close"></span>;
    }
    const iconClass = props.expanded ? 'fas fa-folder-open' : 'fas fa-folder';
    return <i className={`${iconClass} me-1 rc-tree-switcher-icon`}></i>;
  };

  const titleRender = (nodeData) => (
    <CustomTreeNode
      nodeData={nodeData}
      onMoveUser={handleMoveUser}
      onHoverExpand={handleHoverExpand}
      isExpanded={expandedKeys.includes(nodeData.key)}
      isSelected={selectedKeys.includes(nodeData.key)}
    />
  );

  if (loading) return <div className="p-3 text-center">Carregando árvore...</div>;
  if (error) return <div className="p-3 text-center text-danger">{error}</div>;

  return (
    <Tree
      treeData={treeData}
      onSelect={handleSelect}
      onExpand={setExpandedKeys}
      expandedKeys={expandedKeys}
      selectedKeys={selectedKeys}
      showLine
      switcherIcon={switcherIcon}
      titleRender={titleRender}
      motion={null} // Desativa animações para melhor performance
    />
  );
};

export default OuTree;