#!/usr/bin/env bash
# ==============================================================================
# share-connection: Installer script
# https://github.com/musicOverdose/share-connection
# ==============================================================================

set -e

REPO_URL="https://raw.githubusercontent.com/musicOverdose/share-connection/main/share_connection.py"
INSTALL_DIR="$HOME/.local/bin"
TARGET_FILE="$INSTALL_DIR/share-connection"

echo "=================================================================="
echo "  🚀 Installing share-connection (Universal VPN Sharing)..."
echo "=================================================================="

# Check Python 3
if ! command -v python3 &>/dev/null; then
    echo "❌ Error: Python 3 is required but not installed." >&2
    exit 1
fi

mkdir -p "$INSTALL_DIR"

# Download or copy script
if [ -f "share_connection.py" ]; then
    cp share_connection.py "$TARGET_FILE"
elif [ -f "../share_connection.py" ]; then
    cp ../share_connection.py "$TARGET_FILE"
else
    echo "⬇️  Downloading share_connection.py..."
    curl -fsSL "$REPO_URL" -o "$TARGET_FILE"
fi

chmod +x "$TARGET_FILE"

# Create symlinks
ln -sf "$TARGET_FILE" "$INSTALL_DIR/share-vpn"

echo "✅ Installed successfully to: $TARGET_FILE"

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo ""
    echo "⚠️  Note: $HOME/.local/bin is not in your PATH."
    echo "   Add it by running:"
    echo "     echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
    echo ""
fi

echo "=================================================================="
echo "  🎉 Ready! Run:  share-connection [PORT]"
echo "=================================================================="
