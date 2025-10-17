import React, { forwardRef, useImperativeHandle, useRef } from 'react';
import { Tree } from 'react-arborist';

// O componente Node customizado para se parecer com o que tínhamos
function Node({ node, style, dragHandle }) {
    return (
        <div style={style} ref={dragHandle}>
            <i className={`fas ${node.isOpen ? 'fa-folder-open' : 'fa-folder'} me-2 text-warning`}></i>
            <span>{node.data.text}</span>
        </div>
    );
}

const ReactTreeView = forwardRef(({ treeData, onSelectOU, onMoveUser }, ref) => {
    const treeRef = useRef(null);

    // Adapta o formato dos dados da nossa API para o que react-arborist espera
    const adaptData = (nodes) => {
        if (!nodes) return [];
        return nodes.map(node => ({
            id: node.id,
            text: node.text,
            children: adaptData(node.children),
        }));
    };

    const adaptedData = adaptData(treeData);

    const handleSelect = (nodes) => {
        // Pega o primeiro nó selecionado (a biblioteca suporta multiselect)
        const selectedNode = nodes[0];
        if (selectedNode) {
            onSelectOU(selectedNode.id, selectedNode.data.text);
        }
    };

    const handleMove = ({ dragIds, parentId }) => {
        // Pega o primeiro usuário arrastado e o alvo
        const userId = dragIds[0];
        const targetOuId = parentId;
        if (userId && targetOuId) {
            onMoveUser(userId, targetOuId);
        }
    };

    // Expõe a função de navegar para a OU para o componente pai
    useImperativeHandle(ref, () => ({
        navigateToOU: (ou_dn) => {
            if (treeRef.current) {
                treeRef.current.open(ou_dn);
                treeRef.current.select(ou_dn);
            }
        }
    }));

    if (!adaptedData || adaptedData.length === 0) {
        return <div className="text-center text-muted p-4">Nenhuma Unidade Organizacional encontrada.</div>;
    }

    return (
        <Tree
            ref={treeRef}
            data={adaptedData}
            onSelect={handleSelect}
            onMove={handleMove}
            width="100%"
            height={600} // Altura fixa para o contêiner da árvore
        >
            {Node}
        </Tree>
    );
});

export default ReactTreeView;