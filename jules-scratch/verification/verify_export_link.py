from playwright.sync_api import sync_playwright, expect
import time

def run_verification():
    """
    Verifica se o link 'Exportar Base AD' está visível no dashboard.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        try:
            # 1. Navega para a página do dashboard
            page.goto("http://127.0.0.1:5000/dashboard", timeout=60000)

            # 2. Aguarda e verifica se o título da página está correto
            expect(page).to_have_title("Dashboard - Monitoramento do Ambiente", timeout=10000)

            # 3. Verifica se o link de exportação está visível
            export_link = page.get_by_role("link", name="Exportar Base AD")
            expect(export_link).to_be_visible()

            # 4. Aguarda um pouco para garantir que a página esteja totalmente renderizada
            time.sleep(1)

            # 5. Tira a screenshot para verificação visual
            screenshot_path = "jules-scratch/verification/export_link_verification.png"
            page.screenshot(path=screenshot_path)

            print(f"Verificação do link de exportação concluída com sucesso. Screenshot salva em {screenshot_path}")

        except Exception as e:
            print(f"Ocorreu um erro durante a verificação do frontend: {e}")

        finally:
            browser.close()

if __name__ == "__main__":
    run_verification()