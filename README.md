# AD User Management Web Application

This is a web application built with Python and Flask to create and manage users in an Active Directory (AD) environment. This version is a hybrid, combining a secure, configurable application shell with detailed, environment-specific AD logic.

## Features

-   **Secure Admin Setup:** A first-time-run wizard to create a master administrator account for the application.
-   **Web-Based Configuration:** All AD settings (server, default password, search base) are managed via a secure admin UI.
-   **AD User Authentication:** Login for Domain Admins using their own AD credentials.
-   **User Creation:** Create new AD users by cloning attributes (OU, groups, etc.) and UPN suffix from a model user.
-   **Full User Management:**
    -   Search for users by name or login.
    -   View a user's detailed AD attributes.
    -   See user account status (Active, Disabled, Locked).
    -   Enable and disable user accounts.
    -   Reset user passwords to the configured default.
-   **Audit Logging:** All major actions (user creation, status changes, password resets) are logged to a file, including which admin performed the action. An admin-only page is available to view these logs.

## Setup and Installation

1.  **Prerequisites:**
    -   Python 3.
    -   A shell environment (like Bash on Linux/macOS).

2.  **Automated Setup:**
    For a quick setup, use the provided shell script. Open your terminal in the project's root directory and run:
    ```bash
    # Make the script executable (only need to do this once)
    chmod +x install.sh

    # Run the script
    ./install.sh
    ```
    The script will create a Python virtual environment (`venv`), install all dependencies, and then launch the application server.

3.  **Manual Setup:**
    -   Create a virtual environment: `python3 -m venv venv`
    -   Activate it: `source venv/bin/activate`
    -   Install dependencies: `pip install -r requirements.txt`

## Initial Configuration & First Use

1.  **Run the Application:**
    If you used `install.sh`, the app is already running. If not, run `flask run`. The application will be available at `http://127.0.0.1:5000`.

2.  **Create Master Admin Account:**
    When you first access the application, you will be automatically redirected to the **Admin Registration** page. Create a master administrator username and password. This account is used *only* to access the application's configuration page.

3.  **Log In as Admin:**
    After registering, you will be redirected to the Admin Login page (`/admin/login`). Log in with the credentials you just created.

4.  **Configure Active Directory Settings:**
    You will be taken to the AD Configuration page. Fill in all the details for your Active Directory environment:
    -   **AD Server:** The hostname or IP of your domain controller.
    -   **Default Password for New Users:** The password that will be assigned to newly created users.
    -   **AD Search Base:** The OU path where the application will search for and create users (e.g., `OU=Users,DC=domain,DC=com`).

5.  **Start Using the Application:**
    Once the configuration is saved, you can log out of the admin section (or open a new browser tab) and go to the main login page (`/login`). Now, Domain Admins can log in with their own AD credentials to start creating and managing users.