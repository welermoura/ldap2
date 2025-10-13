import re
from playwright.sync_api import Playwright, sync_playwright, expect

def run(playwright: Playwright) -> None:
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()

    # Admin Registration & Login
    page.goto("http://localhost:5000/admin/login")
    page.wait_for_load_state()
    print(page.url)
    # Check if we need to register first
    if "register" in page.url:
        print("On registration page, attempting to fill form...")
        expect(page.get_by_placeholder("Nome de Usuário do Admin")).to_be_visible()
        page.get_by_placeholder("Nome de Usuário do Admin").fill("admin")
        page.get_by_placeholder("Senha (mín. 8 caracteres)").fill("adminadmin")
        page.get_by_placeholder("Confirmar Senha").fill("adminadmin")
        page.get_by_role("button", name="Registrar Admin").click()
        expect(page).to_have_url(re.compile(r'.*/admin/login'))

    page.get_by_placeholder("Nome de Usuário do Admin").fill("admin")
    page.get_by_placeholder("Senha").fill("adminadmin")
    page.get_by_role("button", name="Entrar").click()
    expect(page).to_have_url(re.compile(r'.*/admin/dashboard'))

    # Navigate to permissions and set them
    page.goto("http://localhost:5000/admin/permissions")
    page.get_by_placeholder("Buscar por nome do grupo...").fill("Administrators")
    page.get_by_role("button", name="Buscar").click()
    page.get_by_role("button", name="Administrators").click()
    page.get_by_label("Personalizado").check()
    page.get_by_label("Card: Estatísticas de Usuários").check()
    page.get_by_role("button", name="Salvar Permissões").click()
    expect(page.get_by_role("alert")).to_contain_text("Permissões salvas com sucesso!")

    # Logout from admin
    page.goto("http://localhost:5000/admin/logout")
    expect(page).to_have_url(re.compile(r'.*/admin/login'))

    # User Login
    page.goto("http://localhost:5000/login")
    page.get_by_placeholder("Nome de Usuário").fill("testuser")
    page.get_by_placeholder("Senha").fill("password")
    page.get_by_role("button", name="Entrar").click()
    expect(page).to_have_url("http://localhost:5000/dashboard")

    # Verify dashboard cards
    expect(page.get_by_text("Contas Ativas")).to_be_visible()
    expect(page.get_by_text("Contas Desativadas")).to_be_visible()
    expect(page.get_by_text("Desativados (Última Semana)")).not_to_be_visible()
    expect(page.get_by_text("Reativações (Próx. 7 dias)")).not_to_be_visible()
    expect(page.get_by_text("Desativações (Próx. 7 dias)")).not_to_be_visible()
    expect(page.get_by_text("Senhas Expirando")).not_to_be_visible()

    page.screenshot(path="jules-scratch/verification/verification.png")

    # Reset permissions
    page.goto("http://localhost:5000/admin/login")
    page.get_by_label("Nome de Usuário do Admin").fill("admin")
    page.get_by_label("Senha do Admin").fill("admin")
    page.get_by_role("button", name="Entrar").click()
    page.goto("http://localhost:5000/admin/permissions")
    page.get_by_label("Buscar por nome do grupo...").fill("Administrators")
    page.get_by_role("button", name="Buscar").click()
    page.get_by_role("button", name="Administrators").click()
    page.get_by_label("Acesso Total").check()
    page.get_by_role("button", name="Salvar Permissões").click()

    context.close()
    browser.close()

with sync_playwright() as playwright:
    run(playwright)