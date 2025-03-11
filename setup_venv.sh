#!/bin/bash

# Ensure python3-venv is installed
echo "Installing python3-venv if needed..."
sudo apt-get update
sudo apt-get install -y python3-full python3-venv

# Create a virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate the virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install requirements
echo "Installing requirements..."
pip install -r requirements.txt

# Inform the user
echo ""
echo "✅ Setup complete!"
echo ""
echo "To activate the virtual environment in the future, run:"
echo "    source venv/bin/activate"
echo ""
echo "To run your application after activating, use:"
echo "    python main.py"
echo ""
echo "To deactivate the virtual environment when finished, run:"
echo "    deactivate"
