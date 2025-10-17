import React, { useState, useRef, useImperativeHandle, forwardRef } from 'react';
import { useDrop } from 'react-dnd';
import { ItemTypes } from './UserList';

const OUNode = ({ node, onSelectOU, onMoveUser, openPaths, setOpenPaths }) => {
    // Um nó está aberto se seu caminho estiver no conjunto de caminhos abertos.
    const isOpen = openPaths.has(node.id);
    const ref = useRef(null);

    const [{ canDrop, isOver }, drop] = useDrop(() => ({
        accept: ItemTypes.USER,
        drop: (item) => onMoveUser(item.id, node.id),
        hover: (item, monitor) => {
            if (!isOpen) {
                setOpenPaths(prev => new Set(prev).add(node.id));
            }
        },
        collect: (monitor) => ({
            isOver: monitor.isOver(),
            canDrop: monitor.canDrop(),
        }),
    }));

    drop(ref);

    const hasChildren = node.children && node.children.length > 0;

    const handleToggle = () => {
        setOpenPaths(prev => {
            const newPaths = new Set(prev);
            if (newPaths.has(node.id)) {
                newPaths.delete(node.id);
            } else {
                newPaths.add(node.id);
            }
            return newPaths;
        });
    };

    const handleSelect = (e) => {
        e.stopPropagation();
        onSelectOU(node.id, node.text);
    };

    let backgroundColor = 'transparent';
    if (canDrop && isOver) {
        backgroundColor = 'rgba(0, 123, 255, 0.2)';
    }

    return (
        <div ref={ref} style={{ marginLeft: '20px', backgroundColor, borderRadius: '4px' }}>
            <div className="ou-node" style={{ cursor: 'pointer', padding: '5px' }}>
                {hasChildren && (
                    <i className={`fas ${isOpen ? 'fa-caret-down' : 'fa-caret-right'} me-2`} onClick={handleToggle}></i>
                )}
                <i className={`fas ${isOpen ? 'fa-folder-open' : 'fa-folder'} me-2 text-warning`} onClick={handleToggle}></i>
                <span onClick={handleSelect}>{node.text}</span>
            </div>
            {isOpen && hasChildren && (
                <div style={{ borderLeft: '1px solid var(--glass-border-color)', marginLeft: '10px' }}>
                    <OUTreeInner treeData={node.children} onSelectOU={onSelectOU} onMoveUser={onMoveUser} openPaths={openPaths} setOpenPaths={setOpenPaths} />
                </div>
            )}
        </div>
    );
};

// Separamos o componente interno para o forwardRef funcionar corretamente
const OUTreeInner = ({ treeData, onSelectOU, onMoveUser, openPaths, setOpenPaths }) => {
    return (
        <div>
            {treeData.map(node => (
                <OUNode key={node.id} node={node} onSelectOU={onSelectOU} onMoveUser={onMoveUser} openPaths={openPaths} setOpenPaths={setOpenPaths} />
            ))}
        </div>
    );
};

const OUTree = forwardRef(({ treeData, onSelectOU, onMoveUser }, ref) => {
    const [openPaths, setOpenPaths] = useState(() => {
        const initialOpen = new Set();
        if (treeData && treeData.length > 0) {
            initialOpen.add(treeData[0].id); // Começa com o nó raiz aberto
        }
        return initialOpen;
    });

    useImperativeHandle(ref, () => ({
        navigateToOU: (ou_dn) => {
            // Lógica para abrir a árvore até a OU e selecioná-la
            const dnParts = ou_dn.split(',');
            const pathsToOpen = new Set();
            for (let i = 0; i < dnParts.length; i++) {
                pathsToOpen.add(dnParts.slice(i).join(','));
            }
            setOpenPaths(prev => new Set([...prev, ...pathsToOpen]));
            onSelectOU(ou_dn, dnParts[0].split('=')[1]);
        }
    }));

    if (!treeData || treeData.length === 0) return null;

    return <OUTreeInner treeData={treeData} onSelectOU={onSelectOU} onMoveUser={onMoveUser} openPaths={openPaths} setOpenPaths={setOpenPaths} />;
});

export default OUTree;