import React from "react";
import { Tree } from "@minoru/react-dnd-treeview";
import { ItemTypes } from './UserList.jsx'; // Reutilizamos a definição de tipo

const OUTree = ({ treeData, onSelectOU, onMoveUser }) => {

    // A função onMoveUser já está no formato correto para o `onDrop` da árvore.
    // Ela espera o nó (usuário) e o novo pai (OU).
    const handleDrop = (newTreeData, { dragSourceId, dropTargetId }) => {
        // dragSourceId é o ID do usuário (item.id)
        // dropTargetId é o ID da OU (node.id)
        onMoveUser(dragSourceId, dropTargetId);
    };

    return (
        <Tree
            treeData={treeData}
            rootId={0} // Um ID raiz virtual, já que podemos ter múltiplas bases
            render={(node, { depth, isOpen, onToggle }) => (
                <div
                    style={{ marginLeft: depth * 10 }}
                    className="ou-node"
                    onClick={() => onSelectOU(node.id, node.text)}
                >
                    {node.droppable && (
                        <span onClick={(e) => { e.stopPropagation(); onToggle(); }}>
                            <i className={`fas ${isOpen ? 'fa-caret-down' : 'fa-caret-right'} me-2`}></i>
                        </span>
                    )}
                    <i className={`fas ${isOpen ? 'fa-folder-open' : 'fa-folder'} me-2 text-warning`}></i>
                    {node.text}
                </div>
            )}
            dragPreviewRender={(monitorProps) => (
                <div className="p-2 bg-primary text-white rounded">
                    {monitorProps.item.text}
                </div>
            )}
            onDrop={handleDrop}
            // Mapeia o tipo de arrastar do nosso UserList para a árvore
            canDrop={(tree, { dragSource }) => {
                if (dragSource && dragSource.type === ItemTypes.USER) {
                    return true;
                }
            }}
            // Define o tipo de item que pode ser arrastado para a árvore
            dropTarget={{
                "type": ItemTypes.USER,
                "resolve": "manual"
            }}
        />
    );
};

export default OUTree;