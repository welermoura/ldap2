import React, { useState } from 'react';

const SearchUser = ({ onSearch, onResult, showAlert }) => {
    const [query, setQuery] = useState('');
    const [isSearching, setIsSearching] = useState(false);
    const [searchMessage, setSearchMessage] = useState(null);

    const handleSearch = (e) => {
        e.preventDefault();
        if (query.length < 3) {
            showAlert('Digite pelo menos 3 caracteres para buscar.', 'warning');
            return;
        }
        setIsSearching(true);
        setSearchMessage(null);

        onSearch(query)
            .then(response => {
                const data = response.data;
                setSearchMessage({
                    type: 'success',
                    text: `Usuário encontrado! Navegando para: ${data.ou_path.replace(/ --- /g, ' / ')}`
                });
                onResult(data);
            })
            .catch(error => {
                const errorMessage = error.response?.data?.error || 'Erro ao buscar usuário.';
                setSearchMessage({ type: 'danger', text: errorMessage });
            })
            .finally(() => {
                setIsSearching(false);
            });
    };

    return (
        <div className="card glass-card">
            <div className="card-body">
                <h5 className="card-title"><i className="fas fa-search me-2"></i>Buscar Usuário</h5>
                <form onSubmit={handleSearch} className="d-flex">
                    <input
                        type="text"
                        className="form-control me-2"
                        placeholder="Digite nome ou login..."
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        disabled={isSearching}
                    />
                    <button type="submit" className="btn btn-primary" disabled={isSearching}>
                        {isSearching ? <span className="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> : 'Buscar'}
                    </button>
                </form>
                {searchMessage && (
                    <div className={`alert alert-${searchMessage.type} mt-3`}>
                        {searchMessage.text}
                    </div>
                )}
            </div>
        </div>
    );
};

export default SearchUser;