import React from "react";
import { Tree } from "@minoru/react-dnd-treeview";
import { ItemTypes } from './UserList.jsx';

const OUTree = ({ treeData, onSelectOU, onMoveUser }) => {

    // A função onMoveUser espera o DN da OU, que está em `dropTarget.data.dn`
    const handleDrop = (newTreeData, { dragSourceId, dropTarget }) => {
        if (dropTarget?.data?.dn) {
            onMoveUser(dragSourceId, dropTarget.data.dn);
        } else {
            console.error("Não foi possível mover o usuário: DN da OU de destino não encontrado.");
        }
    };

    return (
        <Tree
            treeData={treeData}
            rootId={0}
            render={(node, { depth, isOpen, onToggle }) => (
                <div
                    style={{ marginLeft: depth * 10 }}
                    className="ou-node"
                    // Ao selecionar, passamos o DN e o texto
                    onClick={() => onSelectOU(node.data.dn, node.text)}
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
            canDrop={(tree, { dragSource }) => dragSource?.type === ItemTypes.USER}
            dropTarget={{
                "type": ItemTypes.USER,
                "resolve": "manual"
            }}
        />
    );
};

export default OUTree;