import React, { useState, useRef, useImperativeHandle, forwardRef, useEffect, useCallback } from 'react';
import { useDrop } from 'react-dnd';
import { ItemTypes } from './UserList.jsx';

const OUNode = forwardRef(({ node, onSelectOU, onMoveUser, openPaths, onToggleNode }, ref) => {
    const isOpen = openPaths.has(node.id);

    const [{ canDrop, isOver }, drop] = useDrop(() => ({
        accept: ItemTypes.USER,
        drop: (item) => onMoveUser(item.id, node.id),
        hover: () => {
            if (!isOpen) {
                onToggleNode(node.id);
            }
        },
        collect: (monitor) => ({
            isOver: monitor.isOver(),
            canDrop: monitor.canDrop(),
        }),
    }));

    const hasChildren = node.children && node.children.length > 0;

    const handleSelect = (e) => {
        e.stopPropagation();
        onSelectOU(node.id, node.text);
    };

    const handleToggle = () => {
        onToggleNode(node.id);
    };

    let backgroundColor = 'transparent';
    if (canDrop && isOver) {
        backgroundColor = 'rgba(0, 123, 255, 0.2)';
    }

    return (
        <div ref={drop} style={{ marginLeft: '20px', backgroundColor, borderRadius: '4px' }}>
            <div className="ou-node" style={{ cursor: 'pointer', padding: '5px' }}>
                {hasChildren && (
                    <i className={`fas ${isOpen ? 'fa-caret-down' : 'fa-caret-right'} me-2`} onClick={handleToggle}></i>
                )}
                <i className={`fas ${isOpen ? 'fa-folder-open' : 'fa-folder'} me-2 text-warning`} onClick={handleToggle}></i>
                <span onClick={handleSelect}>{node.text}</span>
            </div>
            {isOpen && hasChildren && (
                <div style={{ borderLeft: '1px solid var(--glass-border-color)', marginLeft: '10px' }}>
                    {node.children.map(childNode => (
                        <OUNode
                            key={childNode.id}
                            node={childNode}
                            onSelectOU={onSelectOU}
                            onMoveUser={onMoveUser}
                            openPaths={openPaths}
                            onToggleNode={onToggleNode}
                        />
                    ))}
                </div>
            )}
        </div>
    );
});

const OUTree = forwardRef(({ treeData, onSelectOU, onMoveUser }, ref) => {
    const [openPaths, setOpenPaths] = useState(new Set());

    useEffect(() => {
        // Abre o nó raiz por padrão quando os dados da árvore são carregados pela primeira vez
        if (treeData && treeData.length > 0 && openPaths.size === 0) {
            setOpenPaths(new Set([treeData[0].id]));
        }
    }, [treeData]); // Depende apenas de treeData

    const handleToggleNode = useCallback((nodeId) => {
        setOpenPaths(prevPaths => {
            const newPaths = new Set(prevPaths);
            if (newPaths.has(nodeId)) {
                newPaths.delete(nodeId);
            } else {
                newPaths.add(nodeId);
            }
            return newPaths;
        });
    }, []); // A função em si não muda

    useImperativeHandle(ref, () => ({
        navigateToOU: (ou_dn) => {
            const dnParts = ou_dn.split(',');
            const pathsToOpen = new Set();
            for (let i = 0; i < dnParts.length; i++) {
                pathsToOpen.add(dnParts.slice(i).join(','));
            }
            setOpenPaths(prev => new Set([...prev, ...pathsToOpen]));
            // Seleciona a OU após um pequeno atraso para garantir que ela esteja visível
            setTimeout(() => onSelectOU(ou_dn, dnParts[0].split('=')[1]), 100);
        }
    }), [onSelectOU]); // Depende de onSelectOU

    if (!treeData || treeData.length === 0) {
        return <div className="text-center text-muted p-4">Nenhuma Unidade Organizacional encontrada.</div>;
    }

    return (
        <div>
            {treeData.map(node => (
                <OUNode
                    key={node.id}
                    node={node}
                    onSelectOU={onSelectOU}
                    onMoveUser={onMoveUser}
                    openPaths={openPaths}
                    onToggleNode={handleToggleNode}
                />
            ))}
        </div>
    );
});

export default OUTree;