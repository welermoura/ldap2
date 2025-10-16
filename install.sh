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

# --- Set Permissions ---
echo "Setting permissions for data and logs directories..."
mkdir -p data logs
chown -R www-data:www-data data logs
chmod -R 775 data logs
touch logs/ad_creator.log
chmod 666 logs/ad_creator.log

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

# Check Node.js version and install/update if necessary
NODE_MAJOR_VERSION=0
if command -v node &> /dev/null; then
    NODE_MAJOR_VERSION=$(node -v | cut -d. -f1 | sed 's/v//')
fi

if [ "$NODE_MAJOR_VERSION" -lt 20 ]; then
    echo "Node.js version is older than 20 or not installed. Attempting to install/upgrade..."
    # Ensure the script is run as root for system-wide installations
    if [ "$(id -u)" -ne 0 ]; then
        echo "Error: This script requires root privileges to install Node.js. Please run with sudo."
        exit 1
    fi

    # Update package lists and install curl if not present
    apt-get update
    apt-get install -y curl

    # Use NodeSource repository to get a modern version of Node.js
    echo "Configuring NodeSource repository for Node.js 20.x..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -

    # Install Node.js
    echo "Installing Node.js..."
    apt-get install -y nodejs

    echo "Node.js installation/upgrade complete."
else
    echo "Node.js version is compatible (v$NODE_MAJOR_VERSION). Skipping installation."
fi

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

# --- Set Final Ownership ---
echo "Setting final ownership of all project files to www-data..."
chown -R www-data:www-data .

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