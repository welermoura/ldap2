from playwright.sync_api import sync_playwright, expect

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()

    try:
        # Navega para a página de login
        page.goto("http://127.0.0.1:5000/login", wait_until="networkidle")

        # Espera o botão de tema estar visível
        theme_toggle = page.locator("#theme-toggle")
        expect(theme_toggle).to_be_visible()

        # Tira o screenshot inicial
        page.screenshot(path="jules-scratch/verification/theme_initial_fixed.png")
        print("Screenshot do tema inicial (corrigido) capturado.")

        # Clica para alternar o tema
        theme_toggle.click()

        # Espera um pouco para a transição do CSS
        page.wait_for_timeout(500)

        # Tira o screenshot do tema alternado
        page.screenshot(path="jules-scratch/verification/theme_toggled_fixed.png")
        print("Screenshot do tema alternado (corrigido) capturado.")

    except Exception as e:
        print(f"Ocorreu um erro: {e}")
        page.screenshot(path="jules-scratch/verification/error.png")
        raise
    finally:
        browser.close()

if __name__ == "__main__":
    with sync_playwright() as p:
        run(p)