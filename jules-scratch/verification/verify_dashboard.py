from playwright.sync_api import sync_playwright, expect
import time

def run_verification():
    """
    Verifica se o novo dashboard é renderizado corretamente.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        try:
            # 1. Navega para a página do dashboard
            # A autenticação foi temporariamente desabilitada para este teste
            page.goto("http://127.0.0.1:5000/dashboard", timeout=60000)

            # 2. Aguarda e verifica se o título da página está correto
            expect(page).to_have_title("Dashboard - Monitoramento do Ambiente", timeout=10000)

            # 3. Verifica se o cabeçalho principal está visível
            heading = page.get_by_role("heading", name="Monitoramento do Ambiente")
            expect(heading).to_be_visible()

            # 4. Verifica se o painel "Senhas Expirando" está presente
            expiring_passwords_panel = page.get_by_role("heading", name="Senhas Expirando (Próximos 15 dias)")
            expect(expiring_passwords_panel).to_be_visible()

            # 5. Aguarda um pouco para garantir que o JS tenha tempo de renderizar
            time.sleep(2)

            # 6. Tira a screenshot para verificação visual
            screenshot_path = "jules-scratch/verification/dashboard_verification.png"
            page.screenshot(path=screenshot_path)

            print(f"Verificação do frontend concluída com sucesso. Screenshot salva em {screenshot_path}")

        except Exception as e:
            print(f"Ocorreu um erro durante a verificação do frontend: {e}")

        finally:
            browser.close()

if __name__ == "__main__":
    run_verification()