import React from 'react';

class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null, errorInfo: null };
    }

    static getDerivedStateFromError(error) {
        // Atualiza o estado para que a próxima renderização mostre a UI de fallback.
        return { hasError: true };
    }

    componentDidCatch(error, errorInfo) {
        // Você também pode registrar o erro em um serviço de log de erros
        console.error("Erro capturado pelo Error Boundary:", error, errorInfo);
        this.setState({ error: error, errorInfo: errorInfo });
    }

    render() {
        if (this.state.hasError) {
            // Você pode renderizar qualquer UI de fallback personalizada
            return (
                <div className="alert alert-danger">
                    <h4><i className="fas fa-exclamation-triangle me-2"></i>Ocorreu um erro ao carregar este componente.</h4>
                    <p>Por favor, recarregue a página. Se o erro persistir, contate o suporte.</p>
                    <details style={{ whiteSpace: 'pre-wrap' }}>
                        {this.state.error && this.state.error.toString()}
                        <br />
                        {this.state.errorInfo && this.state.errorInfo.componentStack}
                    </details>
                </div>
            );
        }

        return this.props.children;
    }
}

export default ErrorBoundary;