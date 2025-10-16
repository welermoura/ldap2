import re
from playwright.sync_api import sync_playwright, Page, expect

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()

    try:
        # 1. Navega para a aplicação, que deve redirecionar para o registro do admin
        page.goto("http://127.0.0.1:5000/")

        # Espera pela página de registro
        expect(page.get_by_role("heading", name="Registro do Admin")).to_be_visible(timeout=10000)

        # 2. Registra um novo admin
        print("Registrando um novo administrador...")
        page.get_by_placeholder("Nome de Usuário do Admin").fill("admin")
        page.get_by_placeholder("Senha (mín. 8 caracteres)").fill("password123")
        page.get_by_placeholder("Confirmar Senha").fill("password123")
        page.get_by_role("button", name="Registrar Admin").click()

        # 3. Faz login como o admin recém-criado
        print("Fazendo login como administrador...")
        expect(page.get_by_role("heading", name="Login do Admin")).to_be_visible(timeout=10000)
        page.get_by_placeholder("Nome de Usuário do Admin").fill("admin")
        page.get_by_placeholder("Senha do Admin").fill("password123")
        page.get_by_role("button", name="Entrar").click()

        # 4. Vai para o dashboard do admin e depois para a página de configuração
        print("Navegando para a configuração do AD...")
        expect(page.get_by_role("heading", name="Painel do Administrador")).to_be_visible(timeout=10000)
        page.get_by_role("link", name="Configuração do AD").click()

        # 5. Preenche a configuração mínima para evitar erros de API
        print("Preenchendo configuração do AD...")
        expect(page.get_by_role("heading", name="Configuração do Active Directory")).to_be_visible(timeout=10000)
        page.get_by_label("Servidor AD").fill("dc.example.com")
        page.get_by_label("Domínio (NetBIOS name, ex: MEUDOMINIO)").fill("EXAMPLE")
        page.get_by_label("Base de Busca AD").fill("DC=example,DC=com")
        page.get_by_label("Usuário de Serviço").fill("service_user")
        page.get_by_label("Senha do Usuário de Serviço").fill("service_password")
        page.get_by_role("button", name="Salvar Configuração").click()

        # 6. Faz logout do admin para poder logar como usuário AD
        print("Fazendo logout do admin...")
        page.get_by_role("link", name="Sair do Admin").click()

        # 7. Tenta fazer login como um usuário do AD. Isso vai falhar, mas criará uma sessão de usuário não-admin.
        print("Fazendo login como usuário do AD...")
        expect(page.get_by_role("heading", name="Login")).to_be_visible(timeout=10000)
        page.get_by_placeholder("Nome de Usuário").fill("testuser")
        page.get_by_placeholder("Senha").fill("testpassword")
        page.get_by_role("button", name="Entrar").click()

        # A página de login deve mostrar um erro, mas a sessão agora existe.
        expect(page.locator(".alert")).to_be_visible()

        # 8. Navega para a página de gerenciamento de OUs
        print("Navegando para a página de gerenciamento de OUs...")
        page.goto("http://127.0.0.1:5000/ou_management")

        # 9. Tira a captura de tela
        # Espera que o título da página esteja visível
        expect(page.get_by_role("heading", name="Gerenciamento de Unidades Organizacionais")).to_be_visible(timeout=15000)

        # A API vai falhar, então esperamos ver uma mensagem de erro na UI.
        expect(page.get_by_text("Falha ao carregar a árvore de OUs.")).to_be_visible(timeout=10000)

        page.screenshot(path="jules-scratch/verification/verification.png")
        print("Captura de tela tirada com sucesso.")

    except Exception as e:
        print(f"Ocorreu um erro durante a verificação: {e}")
        page.screenshot(path="jules-scratch/verification/error.png")
    finally:
        browser.close()

with sync_playwright() as playwright:
    run(playwright)