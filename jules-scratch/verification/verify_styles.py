from playwright.sync_api import sync_playwright, expect
import time

def run_verification():
    """
    Verifica se os novos estilos de fonte e fundo foram aplicados corretamente.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        try:
            # 1. Navega para a página do dashboard
            page.goto("http://127.0.0.1:5000/dashboard", timeout=60000)

            # 2. Aguarda e verifica se o título da página está correto
            expect(page).to_have_title("Dashboard - Monitoramento do Ambiente", timeout=10000)

            # 3. Encontra e clica no cartão "Contas Desativadas" para abrir o modal
            disabled_card = page.get_by_role("heading", name="Contas Desativadas").locator('..').locator('..').locator('..')
            disabled_card.click()

            # 4. Aguarda o modal estar visível
            modal = page.locator("#dataModal")
            expect(modal).to_be_visible(timeout=5000)

            # 5. Aguarda um pouco para garantir que a animação do modal termine
            time.sleep(1)

            # 6. Tira a screenshot para verificação visual
            screenshot_path = "jules-scratch/verification/style_verification.png"
            page.screenshot(path=screenshot_path)

            print(f"Verificação de estilo concluída com sucesso. Screenshot salva em {screenshot_path}")

        except Exception as e:
            print(f"Ocorreu um erro durante a verificação de estilo: {e}")

        finally:
            browser.close()

if __name__ == "__main__":
    run_verification()