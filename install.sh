#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

echo "--- Starting Environment Setup ---"

# --- Find Python 3 Executable ---
PYTHON_EXEC=""
if command -v python3 &> /dev/null; then
    PYTHON_EXEC="python3"
    echo "Found 'python3' in PATH."
elif [ -f "/usr/bin/python3" ]; then
    PYTHON_EXEC="/usr/bin/python3"
    echo "Found 'python3' at /usr/bin/python3."
else
    echo "Error: Could not find a python3 executable. Please install Python 3."
    exit 1
fi

VENV_DIR="venv"

# --- Create Virtual Environment ---
if [ -d "$VENV_DIR" ]; then
    echo "Virtual environment '$VENV_DIR' already exists. Skipping creation."
else
    echo "Creating Python virtual environment in './$VENV_DIR'..."
    $PYTHON_EXEC -m venv $VENV_DIR
fi

# --- Install Backend Dependencies ---
echo "Installing backend dependencies from requirements.txt..."
$VENV_DIR/bin/pip install -r requirements.txt

# --- Install Frontend Dependencies & Build ---
echo "Checking for frontend build tools (Node.js and npm)..."
if ! command -v node &> /dev/null || ! command -v npm &> /dev/null; then
    echo "Error: Node.js and/or npm are not installed. They are required to build the frontend."
    echo "Please install them to continue. On Debian/Ubuntu, you can use:"
    echo "sudo apt update && sudo apt install nodejs npm"
    exit 1
fi

# Check Node.js version
NODE_MAJOR_VERSION=$(node -v | cut -d. -f1 | sed 's/v//')
if [ "$NODE_MAJOR_VERSION" -lt 20 ]; then
    echo "----------------------------------------------------------------"
    echo "Error: Your Node.js version (v$NODE_MAJOR_VERSION) is too old for this project."
    echo "Vite (our frontend build tool) requires Node.js version 20 or higher."
    echo ""
    echo "We recommend using nvm (Node Version Manager) to easily manage Node.js versions."
    echo "To install or upgrade, please run the following commands in your terminal:"
    echo ""
    echo '1. Install nvm:'
    echo '   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash'
    echo ""
    echo '2. Load nvm (you may need to restart your terminal after installation):'
    echo '   export NVM_DIR="$HOME/.nvm"'
    echo '   [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"'
    echo ""
    echo '3. Install and use the latest Long-Term Support (LTS) version of Node.js:'
    echo '   nvm install --lts'
    echo ""
    echo "After upgrading, please re-run this installation script."
    echo "----------------------------------------------------------------"
    exit 1
fi

echo "Node.js version is compatible. Proceeding with frontend build..."
echo "Installing frontend dependencies and building React app..."
if [ -d "frontend" ]; then
    (
        cd frontend && \
        npm install && \
        npm run build
    )
else
    echo "Warning: 'frontend' directory not found. Skipping frontend build."
fi

# --- Final Instructions ---
echo ""
echo "--- Setup Complete! ---"
echo ""
echo "To run the application manually in the future, first activate the environment:"
echo "source $VENV_DIR/bin/activate"
echo ""
echo "Then run the server:"
echo "flask run"
echo ""
echo "----------------------------------------"
echo "--- Starting Application Server now... ---"
echo "--- Press CTRL+C to stop the server. ---"
"----------------------------------------"

# --- Launch Application ---
$VENV_DIR/bin/python -m flask run