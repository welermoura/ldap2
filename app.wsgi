import sys
import os

# Add the project directory to the Python path
project_home = os.path.dirname(__file__)
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Import the Flask app instance
from app import app as application