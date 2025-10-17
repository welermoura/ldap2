import React from 'react';
import { createRoot } from 'react-dom/client';
import OUManagement from './OUManagement.jsx';

const container = document.getElementById('react-ou-management-root');
if (container) {
    const root = createRoot(container);
    root.render(
        <React.StrictMode>
            <OUManagement />
        </React.StrictMode>
    );
} else {
    console.error("Root element #react-ou-management-root not found.");
}