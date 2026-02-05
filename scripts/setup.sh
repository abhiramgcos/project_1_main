#!/bin/bash
# SOC IoT Toolkit Setup Script
# This script automates the setup process

set -e

echo "=========================================="
echo "SOC IoT Device Discovery Toolkit Setup"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root for nmap capabilities
check_permissions() {
    if [ "$EUID" -eq 0 ]; then
        echo -e "${YELLOW}[!] Running as root. Consider using sudo instead for better security.${NC}"
    fi
}

# Check system dependencies
check_dependencies() {
    echo "[*] Checking system dependencies..."
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        echo -e "${GREEN}[+] Python: $PYTHON_VERSION${NC}"
    else
        echo -e "${RED}[-] Python 3 not found. Please install Python 3.9+${NC}"
        exit 1
    fi
    
    # Check Nmap
    if command -v nmap &> /dev/null; then
        NMAP_VERSION=$(nmap --version | head -n1)
        echo -e "${GREEN}[+] $NMAP_VERSION${NC}"
    else
        echo -e "${RED}[-] Nmap not found. Installing...${NC}"
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y nmap
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y nmap
        elif command -v pacman &> /dev/null; then
            sudo pacman -S --noconfirm nmap
        else
            echo -e "${RED}[-] Could not install nmap. Please install manually.${NC}"
            exit 1
        fi
    fi
    
    # Check Docker
    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version)
        echo -e "${GREEN}[+] $DOCKER_VERSION${NC}"
    else
        echo -e "${YELLOW}[!] Docker not found. PostgreSQL will need manual setup.${NC}"
        echo "    Install Docker: https://docs.docker.com/engine/install/"
    fi
    
    # Check Docker Compose (modern Docker includes 'docker compose')
    if docker compose version &> /dev/null 2>&1; then
        COMPOSE_VERSION=$(docker compose version --short 2>/dev/null || echo "available")
        echo -e "${GREEN}[+] Docker Compose: $COMPOSE_VERSION${NC}"
    elif command -v docker-compose &> /dev/null; then
        echo -e "${GREEN}[+] Docker Compose (standalone) available${NC}"
    else
        echo -e "${YELLOW}[!] Docker Compose not found.${NC}"
    fi
}

# Setup Python virtual environment
setup_venv() {
    echo ""
    echo "[*] Setting up Python virtual environment..."
    
    # Check if venv exists and is valid
    if [ -d "venv" ] && [ -f "venv/bin/activate" ]; then
        echo -e "${YELLOW}[!] Virtual environment already exists${NC}"
    else
        # Remove corrupted venv if exists
        if [ -d "venv" ]; then
            echo "[*] Removing corrupted virtual environment..."
            rm -rf venv
        fi
        python3 -m venv venv
        echo -e "${GREEN}[+] Virtual environment created${NC}"
    fi
    
    source venv/bin/activate
    echo "[*] Installing Python dependencies (this may take a minute)..."
    pip install --upgrade pip
    pip install -r requirements.txt
    echo -e "${GREEN}[+] Dependencies installed${NC}"
}

# Setup environment file
setup_env() {
    echo ""
    echo "[*] Setting up environment configuration..."
    
    if [ ! -f ".env" ]; then
        cp .env.example .env
        echo -e "${GREEN}[+] Environment file created from template${NC}"
        echo -e "${YELLOW}[!] Edit .env file to customize settings${NC}"
    else
        echo -e "${YELLOW}[!] Environment file already exists${NC}"
    fi
}

# Start PostgreSQL with Docker
start_database() {
    echo ""
    echo "[*] Starting PostgreSQL database..."
    
    if command -v docker &> /dev/null; then
        if docker compose version &> /dev/null 2>&1; then
            docker compose up -d
        elif command -v docker-compose &> /dev/null; then
            docker-compose up -d
        fi
        
        echo "[*] Waiting for database to be ready..."
        sleep 5
        
        # Check if container is running
        if docker ps | grep -q soc_iot_postgres; then
            echo -e "${GREEN}[+] PostgreSQL container is running${NC}"
        else
            echo -e "${RED}[-] Failed to start PostgreSQL container${NC}"
            exit 1
        fi
    else
        echo -e "${YELLOW}[!] Docker not available. Please start PostgreSQL manually.${NC}"
    fi
}

# Initialize database schema
init_database() {
    echo ""
    echo "[*] Initializing database schema..."
    
    source venv/bin/activate
    python -m soc_iot_toolkit.database.init_db
    echo -e "${GREEN}[+] Database initialized${NC}"
}

# Print final instructions
print_instructions() {
    echo ""
    echo "=========================================="
    echo -e "${GREEN}Setup Complete${NC}"
    echo "=========================================="
    echo ""
    echo "To run the application:"
    echo ""
    echo "  1. Activate virtual environment:"
    echo "     source venv/bin/activate"
    echo ""
    echo "  2. Start the application (requires sudo for scanning):"
    echo "     sudo \$(which streamlit) run app.py"
    echo ""
    echo "  3. Open in browser:"
    echo "     http://localhost:8501"
    echo ""
    echo "To stop the database:"
    echo "     docker compose down"
    echo ""
    echo "To view logs:"
    echo "     docker compose logs -f postgres"
    echo ""
}

# Main execution
main() {
    check_permissions
    check_dependencies
    setup_venv
    setup_env
    start_database
    init_database
    print_instructions
}

main "$@"
