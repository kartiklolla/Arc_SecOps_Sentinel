#!/bin/bash

# ============================================================================
# Arc_SecOps_Sentinel - Full Quick Start Script
# This script sets up the entire system in a fresh Python virtual environment
# ============================================================================

set -e  # Exit on any error

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║  Arc_SecOps_Sentinel - Complete Quick Start                        ║"
echo "║  Setting up Hero Server + Archestra Integration                   ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

# --- STEP 1: Check Prerequisites ---
echo "📋 Checking prerequisites..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.10+"
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose not found. Please install Docker Compose"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "✅ Python $PYTHON_VERSION found"
echo "✅ Docker found"
echo "✅ Docker Compose found"
echo ""

# --- STEP 2: Create Virtual Environment ---
echo "📦 Step 1: Creating Python virtual environment..."
VENV_DIR="venv-secops"

if [ -d "$VENV_DIR" ]; then
    echo "   Virtual environment already exists at $VENV_DIR"
    read -p "   Delete and recreate? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$VENV_DIR"
        python3 -m venv "$VENV_DIR"
    fi
else
    python3 -m venv "$VENV_DIR"
fi

echo "✅ Virtual environment ready at $VENV_DIR"
echo ""

# --- STEP 3: Activate Virtual Environment ---
echo "🔌 Step 2: Activating virtual environment..."
source "$VENV_DIR/bin/activate"
echo "✅ Virtual environment activated"
echo "   Current Python: $(which python3)"
echo ""

# --- STEP 4: Install Dependencies ---
echo "📥 Step 3: Installing Python dependencies..."
pip install --upgrade pip setuptools wheel > /dev/null 2>&1
pip install -r requirements.txt -q

echo "✅ Dependencies installed"
pip list | grep -E "mcp|httpx|uvicorn|textual|rich|pydantic|python-dotenv"
echo ""

# --- STEP 5: Create .env Configuration ---
echo "⚙️  Step 4: Configuring environment..."
if [ ! -f ".env" ]; then
    cat > .env << 'EOF'
# Archestra Integration Configuration
ARCHESTRA_ENABLED=true
ARCHESTRA_API_URL=http://localhost:9000
ARCHESTRA_API_KEY=

# Agent Configuration
AGENT_NAME=SecOps Sentinel
LOG_LEVEL=INFO
EOF
    echo "✅ Created .env configuration"
else
    echo "✅ .env already exists (using existing config)"
fi
echo ""

# --- STEP 6: Create necessary directories ---
echo "📁 Step 5: Creating necessary directories..."
mkdir -p shared_logs
mkdir -p archestra/data
echo "✅ Directories created"
echo ""

# --- STEP 7: Start Archestra ---
echo "🚀 Step 6: Starting Archestra..."
cd archestra
echo "   Building/downloading Archestra container..."
docker-compose up -d > /dev/null 2>&1
cd ..

# Wait for Archestra to be ready
echo "   Waiting for Archestra to start (10 seconds)..."
sleep 10

# Check if Archestra is running
if curl -s http://localhost:9000/health > /dev/null 2>&1; then
    echo "✅ Archestra started successfully"
    echo "   UI: http://localhost:3000"
    echo "   API: http://localhost:9000"
else
    echo "⚠️  Archestra may still be starting..."
    echo "   If it doesn't start, check: docker logs archestra-ai"
fi
echo ""

# --- STEP 8: Summary and Next Steps ---
echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║  ✅ SETUP COMPLETE                                                  ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""
echo "🎯 Your system is ready! Next steps:"
echo ""
echo "  1️⃣  In a NEW terminal, start the Hero server:"
echo "      source venv-secops/bin/activate"
echo "      cd hero"
echo "      python3 server.py"
echo ""
echo "  2️⃣  In another terminal, run the attack simulator:"
echo "      source venv-secops/bin/activate"
echo "      cd attacker"
echo "      python3 console.py"
echo ""
echo "  3️⃣  Open Archestra UI to view policies:"
echo "      Browser: http://localhost:3000"
echo ""
echo "📚 Documentation:"
echo "   - See INTEGRATION.md for complete setup guide"
echo "   - See POLICIES.md for policy configuration"
echo "   - See ARCHESTRA_CHANGES.md for what changed"
echo ""
echo "🔍 To verify the setup:"
echo "   curl http://localhost:9000/health"
echo "   curl http://localhost:3000"
echo ""
echo "💡 Tip: Keep this terminal open for monitoring Archestra logs"
echo "        docker logs -f archestra-ai"
echo ""
