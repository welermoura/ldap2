import React from 'react';

class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null, errorInfo: null };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true };
    }

    componentDidCatch(error, errorInfo) {
        console.error("Erro de renderização capturado:", error, errorInfo);
        this.setState({ error: error, errorInfo: errorInfo });
    }

    render() {
        if (this.state.hasError) {
            return (
                <div className="alert alert-danger">
                    <h4><i className="fas fa-exclamation-triangle me-2"></i>Ocorreu um erro ao renderizar este componente.</h4>
                    <p>Isso geralmente indica um problema com os dados recebidos ou um bug no componente.</p>
                    <details className="mt-2" style={{ whiteSpace: 'pre-wrap', fontSize: '0.8em' }}>
                        <summary>Detalhes Técnicos</summary>
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