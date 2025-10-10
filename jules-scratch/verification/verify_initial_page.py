from playwright.sync_api import sync_playwright, expect

def run_verification():
    """
    Verifica se a página inicial de registro de admin carrega corretamente.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        try:
            # 1. Navega para a página de registro de administrador
            page.goto("http://127.0.0.1:5000/admin/register")

            # 2. Verifica se o título da página está correto
            expect(page).to_have_title("Registrar Admin Mestre")

            # 3. Verifica se o cabeçalho principal está visível
            heading = page.get_by_role("heading", name="Registro do Administrador Mestre")
            expect(heading).to_be_visible()

            # 4. Tira a screenshot para verificação visual
            page.screenshot(path="jules-scratch/verification/verification.png")

            print("Verificação do frontend concluída com sucesso. Screenshot salva em jules-scratch/verification/verification.png")

        except Exception as e:
            print(f"Ocorreu um erro durante a verificação do frontend: {e}")

        finally:
            browser.close()

if __name__ == "__main__":
    run_verification()