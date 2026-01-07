#!/bin/bash
# Setup and test PROVSAFE

set -e

echo "=== PROVSAFE Setup ==="
echo ""

# Check Python version
echo "Checking Python version..."
python --version

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install package
echo "Installing PROVSAFE..."
pip install -e .

echo ""
echo "=== Running Tests ==="
pytest tests/ -v

echo ""
echo "=== Running Quick Test ==="
python scripts/quick_test.py

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To run evaluations:"
echo "  source venv/bin/activate"
echo "  bash scripts/run_eval.sh"
echo ""
echo "To run tests:"
echo "  pytest tests/ -v"
