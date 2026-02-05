#!/bin/bash
# Quick start script for SOC IoT Toolkit

set -e

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Run scripts/setup.sh first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Check if database is running
if command -v docker &> /dev/null; then
    if ! docker ps | grep -q soc_iot_postgres; then
        echo "[*] Starting PostgreSQL container..."
        if docker compose version &> /dev/null 2>&1; then
            docker compose up -d
        else
            docker-compose up -d
        fi
        sleep 3
    fi
fi

# Run the application
echo "[*] Starting SOC IoT Toolkit..."
echo "[*] Open http://localhost:8501 in your browser"
echo ""

# Check if we need sudo
if [ "$EUID" -ne 0 ]; then
    echo "[!] Running without root privileges. Some scan features may be limited."
    echo "[!] For full scanning capabilities, run: sudo ./scripts/run.sh"
    echo ""
    streamlit run app.py --server.port 8501
else
    streamlit run app.py --server.port 8501
fi
