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

# --- Install Dependencies ---
echo "Installing dependencies from requirements.txt into the virtual environment..."
$VENV_DIR/bin/pip install -r requirements.txt

echo "Installing frontend dependencies from 'frontend/package.json'..."
if [ -d "frontend" ] && [ -f "frontend/package.json" ]; then
    (cd frontend && npm install)
    echo "Frontend dependencies installed. Please run 'npm run build' inside the 'frontend' directory."
else
    echo "Warning: 'frontend' directory or 'package.json' not found. Skipping npm install."
fi

# --- Final Instructions ---
echo ""
echo "--- Setup Complete! ---"
echo ""
echo "--- Post-Installation Steps (Required for Production) ---"
echo "If you are running this application with a web server like Apache/Nginx,"
echo "the server's user (e.g., 'www-data') needs write access to the 'data' directory."
echo "Run the following commands on your server, adjusting the user if necessary:"
echo ""
echo "sudo chown -R www-data:www-data data"
echo "sudo chmod -R 775 data"
echo "----------------------------------------------------------------"
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