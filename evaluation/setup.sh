#!/bin/bash
#
# PROVSAFE Evaluation Setup Script
#
# This script sets up the complete evaluation environment with:
# - Python dependencies
# - Environment configuration
# - SmartThings connection test
# - LLM API connection test
# - Sample evaluation run

set -e

echo "======================================================================"
echo "PROVSAFE Evaluation Environment Setup"
echo "======================================================================"

# Check Python version
echo ""
echo "[1/6] Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "✓ Python $PYTHON_VERSION found"

# Install dependencies
echo ""
echo "[2/6] Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt --quiet
    echo "✓ Dependencies installed"
else
    echo "ERROR: requirements.txt not found"
    exit 1
fi

# Configure environment
echo ""
echo "[3/6] Configuring environment..."
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "✓ Created .env from template"
        echo ""
        echo "⚠️  IMPORTANT: Edit .env and add your SmartThings token:"
        echo "   1. Go to https://account.smartthings.com/tokens"
        echo "   2. Generate new token with permissions: r:devices:*, x:devices:*"
        echo "   3. Update SMARTTHINGS_TOKEN in .env"
        echo ""
        read -p "Press Enter after updating .env to continue..."
    else
        echo "ERROR: .env.example not found"
        exit 1
    fi
else
    echo "✓ .env file exists"
fi

# Test LLM API connection
echo ""
echo "[4/6] Testing LLM API connection..."
python3 <<EOF
import os
import sys
import requests
from dotenv import load_dotenv

load_dotenv()

url = os.getenv("OPENWEBUI_URL")
api_key = os.getenv("OPENWEBUI_API_KEY")

try:
    response = requests.get(url.replace("/chat/completions", "/models"), 
                           headers={"Authorization": f"Bearer {api_key}"},
                           timeout=10)
    if response.status_code == 200:
        print("✓ LLM API connection successful")
        sys.exit(0)
    else:
        print(f"⚠️  LLM API returned status {response.status_code}")
        sys.exit(1)
except Exception as e:
    print(f"✗ LLM API connection failed: {e}")
    sys.exit(1)
EOF

if [ $? -ne 0 ]; then
    echo "WARNING: LLM API connection test failed. Evaluation may not work."
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Test SmartThings connection
echo ""
echo "[5/6] Testing SmartThings API connection..."
python3 <<EOF
import sys
from smartthings_client import SmartThingsClient

try:
    client = SmartThingsClient()
    if client.health_check():
        devices = client.list_devices()
        print(f"✓ SmartThings connected: {len(devices)} devices found")
        for i, device in enumerate(devices[:5], 1):
            print(f"  {i}. {device['label']} ({device['type']})")
        if len(devices) > 5:
            print(f"  ... and {len(devices)-5} more")
        sys.exit(0)
    else:
        print("✗ SmartThings health check failed")
        sys.exit(1)
except Exception as e:
    print(f"✗ SmartThings connection failed: {e}")
    print("\nTroubleshooting:")
    print("  1. Check SMARTTHINGS_TOKEN in .env is valid")
    print("  2. Verify token permissions: r:devices:*, x:devices:*")
    print("  3. Check token at: https://account.smartthings.com/tokens")
    sys.exit(1)
EOF

if [ $? -ne 0 ]; then
    echo ""
    echo "WARNING: SmartThings connection test failed."
    echo "Evaluation will work, but without real device integration."
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Run quick test
echo ""
echo "[6/6] Running quick evaluation test..."
echo "This will test 20 scenarios (takes ~2 minutes)"
read -p "Run quick test? [Y/n] " -n 1 -r
echo

if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    python3 run_evaluation.py --quick
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "======================================================================"
        echo "✓ Setup Complete!"
        echo "======================================================================"
        echo ""
        echo "Quick test passed. You can now run full evaluation:"
        echo ""
        echo "  # Full evaluation (128 scenarios, all 4 models)"
        echo "  python3 run_evaluation.py"
        echo ""
        echo "  # Single model evaluation"
        echo "  python3 run_evaluation.py --models openai/gpt-oss-120b"
        echo ""
        echo "  # Custom output directory"
        echo "  python3 run_evaluation.py --output my_results"
        echo ""
        echo "Results will be saved to: results/YYYYMMDD_HHMMSS/"
        echo ""
    else
        echo ""
        echo "Quick test failed. Check the error messages above."
        exit 1
    fi
else
    echo ""
    echo "======================================================================"
    echo "Setup Complete (test skipped)"
    echo "======================================================================"
    echo ""
    echo "To run evaluation:"
    echo "  python3 run_evaluation.py --quick    # Quick test (20 scenarios)"
    echo "  python3 run_evaluation.py            # Full test (128 scenarios)"
    echo ""
fi
