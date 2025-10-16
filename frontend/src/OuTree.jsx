import React, { useState, useEffect, useRef } from 'react';
import Tree from 'rc-tree';
import { useDrop } from 'react-dnd';
import 'rc-tree/assets/index.css';

const ItemTypes = {
  USER: 'user',
};

const TreeNodeTitle = ({ nodeData, onMoveUser, onHoverExpand, isExpanded }) => {
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
          }, 700);
        }
      }
    },
    collect: (monitor) => ({
      isOver: !!monitor.isOver({ shallow: true }),
      canDrop: !!monitor.canDrop(),
    }),
  }));

  useEffect(() => {
    if (!isOver && timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, [isOver]);

  return (
    <div ref={drop} className="tree-node-title-wrapper" style={{
      backgroundColor: isOver && canDrop ? 'rgba(24, 144, 255, 0.2)' : 'transparent',
      border: isOver && canDrop ? '1px dashed #1890ff' : '1px dashed transparent',
    }}>
      <span>{nodeData.title}</span>
    </div>
  );
};

const OuTree = ({ onSelectOu, onUserMoved, foundUser }) => {
  const [treeData, setTreeData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedKeys, setExpandedKeys] = useState([]);
  const [selectedKeys, setSelectedKeys] = useState([]);
  const [allNodes, setAllNodes] = useState([]);

  const getPathForNode = (key, nodes) => {
    const path = [];
    let currentNode = nodes.find(n => n.key === key);
    while(currentNode) {
        path.unshift(currentNode.title);
        let parentKey = null;
        for(const node of nodes) {
            if(node.children?.some(child => child.key === currentNode.key)) {
                parentKey = node.key;
                break;
            }
        }
        currentNode = parentKey ? nodes.find(n => n.key === parentKey) : null;
    }
    return path.join(' > ');
  };

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

        const adaptedData = adaptData(data);
        setTreeData(adaptedData);

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
        setAllNodes(getAllNodes(adaptedData));
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    if (foundUser && allNodes.length > 0) {
      const { ou_dn } = foundUser;
      const parentDns = getParentDns(ou_dn, allNodes);
      setExpandedKeys([...parentDns, ou_dn]);
      setSelectedKeys([ou_dn]);
      const path = getPathForNode(ou_dn, allNodes);
      onSelectOu({ id: ou_dn, text: path, path: path });
    }
  }, [foundUser, allNodes, onSelectOu]);

  const getParentDns = (ouDn, nodes) => {
    const parents = [];
    let currentKey = ouDn;
    let parentNode;
    do {
        parentNode = nodes.find(n => n.children?.some(c => c.key === currentKey));
        if(parentNode) {
            parents.push(parentNode.key);
            currentKey = parentNode.key;
        }
    } while(parentNode);
    return parents;
  };

  const handleMoveUser = (item, targetOuNode) => {
    if (onUserMoved) {
        onUserMoved(item, targetOuNode);
    }
  };

  const handleHoverExpand = (node) => {
    if (!expandedKeys.includes(node.key)) {
      setExpandedKeys(prevKeys => [...prevKeys, node.key]);
    }
  };

  if (loading) return <p>Carregando...</p>;
  if (error) return <p style={{ color: 'red' }}>{error}</p>;

  const handleSelect = (keys, { node }) => {
    setSelectedKeys(keys);
    if (node) {
      const path = getPathForNode(node.key, allNodes);
      onSelectOu({ id: node.key, text: node.title, path: path });
    }
  };

  const handleExpand = (keys) => {
    setExpandedKeys(keys);
  };

  const switcherIcon = (props) => {
    if (props.isLeaf) {
      // Nó sem filhos, usa um ícone de espaçamento para manter o alinhamento
      return <span className="rc-tree-switcher-icon-leaf-close"></span>;
    }
    const iconClass = props.expanded ? 'fas fa-folder-open' : 'fas fa-folder';
    return <i className={`${iconClass} me-1`} style={{ color: '#f1c40f', cursor: 'pointer' }}></i>;
  };

  const titleRender = (nodeData) => (
    <TreeNodeTitle
      nodeData={nodeData}
      onMoveUser={handleMoveUser}
      onHoverExpand={handleHoverExpand}
      isExpanded={expandedKeys.includes(nodeData.key)}
    />
  );

  return (
    <Tree
      treeData={treeData}
      onSelect={handleSelect}
      onExpand={handleExpand}
      expandedKeys={expandedKeys}
      selectedKeys={selectedKeys}
      showLine
      titleRender={titleRender}
      switcherIcon={switcherIcon}
    />
  );
};

export default OuTree;