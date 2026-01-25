#!/bin/bash
#
# EC Extension Auto-Setup Script
# Automatically installs the EC syntax highlighting extension for your IDE
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${CYAN}${BOLD}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           EC Extension Setup Script                       ║"
echo "║     Syntax highlighting for sentence-based code           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)     OS="linux";;
        Darwin*)    OS="macos";;
        CYGWIN*|MINGW*|MSYS*) OS="windows";;
        *)          OS="unknown";;
    esac
    echo -e "${BLUE}Detected OS:${NC} $OS"
}

# Find IDE extension directories
declare -A IDE_PATHS
declare -A IDE_FOUND

find_ides() {
    echo -e "\n${BLUE}Searching for supported IDEs...${NC}"
    
    # VSCode
    if [ -d "$HOME/.vscode/extensions" ]; then
        IDE_PATHS["vscode"]="$HOME/.vscode/extensions"
        IDE_FOUND["vscode"]=true
        echo -e "  ${GREEN}✓${NC} VSCode found"
    elif [ -d "$HOME/.vscode" ]; then
        mkdir -p "$HOME/.vscode/extensions"
        IDE_PATHS["vscode"]="$HOME/.vscode/extensions"
        IDE_FOUND["vscode"]=true
        echo -e "  ${GREEN}✓${NC} VSCode found (created extensions dir)"
    fi
    
    # Windsurf (check multiple possible locations)
    local windsurf_found=false
    for windsurf_path in "$HOME/.windsurf/extensions" "$HOME/.codeium/windsurf/extensions" "$HOME/.config/Windsurf/extensions"; do
        if [ -d "$windsurf_path" ]; then
            IDE_PATHS["windsurf"]="$windsurf_path"
            IDE_FOUND["windsurf"]=true
            windsurf_found=true
            echo -e "  ${GREEN}✓${NC} Windsurf found"
            break
        fi
    done
    if [ "$windsurf_found" = false ] && [ -d "$HOME/.windsurf" ]; then
        mkdir -p "$HOME/.windsurf/extensions"
        IDE_PATHS["windsurf"]="$HOME/.windsurf/extensions"
        IDE_FOUND["windsurf"]=true
        echo -e "  ${GREEN}✓${NC} Windsurf found (created extensions dir)"
    fi
    
    # Cursor
    if [ -d "$HOME/.cursor/extensions" ]; then
        IDE_PATHS["cursor"]="$HOME/.cursor/extensions"
        IDE_FOUND["cursor"]=true
        echo -e "  ${GREEN}✓${NC} Cursor found"
    elif [ -d "$HOME/.cursor" ]; then
        mkdir -p "$HOME/.cursor/extensions"
        IDE_PATHS["cursor"]="$HOME/.cursor/extensions"
        IDE_FOUND["cursor"]=true
        echo -e "  ${GREEN}✓${NC} Cursor found (created extensions dir)"
    fi
    
    # VSCode Server (remote development)
    if [ -d "$HOME/.vscode-server/extensions" ]; then
        IDE_PATHS["vscode-server"]="$HOME/.vscode-server/extensions"
        IDE_FOUND["vscode-server"]=true
        echo -e "  ${GREEN}✓${NC} VSCode Server (remote) found"
    fi
    
    # Check if any IDEs were found
    if [ ${#IDE_FOUND[@]} -eq 0 ]; then
        echo -e "  ${YELLOW}⚠${NC}  No supported IDEs found"
        echo -e "\n${YELLOW}Supported IDEs:${NC}"
        echo "  - VSCode (~/.vscode/extensions)"
        echo "  - Windsurf (~/.windsurf/extensions)"
        echo "  - Cursor (~/.cursor/extensions)"
        echo -e "\nWould you like to create a directory for one of these? (vscode/windsurf/cursor/n)"
        read -r choice
        case "$choice" in
            vscode)
                mkdir -p "$HOME/.vscode/extensions"
                IDE_PATHS["vscode"]="$HOME/.vscode/extensions"
                IDE_FOUND["vscode"]=true
                ;;
            windsurf)
                mkdir -p "$HOME/.windsurf/extensions"
                IDE_PATHS["windsurf"]="$HOME/.windsurf/extensions"
                IDE_FOUND["windsurf"]=true
                ;;
            cursor)
                mkdir -p "$HOME/.cursor/extensions"
                IDE_PATHS["cursor"]="$HOME/.cursor/extensions"
                IDE_FOUND["cursor"]=true
                ;;
            *)
                echo -e "${RED}Setup cancelled.${NC}"
                exit 1
                ;;
        esac
    fi
}

# Install extension for a specific IDE
install_for_ide() {
    local ide_name="$1"
    local ext_dir="$2"
    local target="$ext_dir/ec"
    
    echo -e "\n${BLUE}Installing for ${BOLD}$ide_name${NC}${BLUE}...${NC}"
    
    # Check if already installed
    if [ -L "$target" ]; then
        local current_target=$(readlink "$target")
        if [ "$current_target" = "$SCRIPT_DIR" ]; then
            echo -e "  ${GREEN}✓${NC} Already installed (symlink exists)"
            return 0
        else
            echo -e "  ${YELLOW}⚠${NC}  Existing symlink points elsewhere: $current_target"
            echo -e "  Updating symlink..."
            rm "$target"
        fi
    elif [ -d "$target" ]; then
        echo -e "  ${YELLOW}⚠${NC}  Existing folder found at $target"
        echo -e "  Would you like to replace it? (y/n)"
        read -r replace
        if [ "$replace" = "y" ]; then
            rm -rf "$target"
        else
            echo -e "  ${YELLOW}Skipped${NC}"
            return 0
        fi
    fi
    
    # Create symlink
    ln -s "$SCRIPT_DIR" "$target"
    
    if [ -L "$target" ]; then
        echo -e "  ${GREEN}✓${NC} Symlink created: $target -> $SCRIPT_DIR"
    else
        echo -e "  ${RED}✗${NC} Failed to create symlink"
        return 1
    fi
}

# Main installation
install_extension() {
    echo -e "\n${BLUE}${BOLD}Installing EC extension...${NC}"
    
    local installed=0
    
    for ide in "${!IDE_FOUND[@]}"; do
        if [ "${IDE_FOUND[$ide]}" = true ]; then
            install_for_ide "$ide" "${IDE_PATHS[$ide]}"
            ((installed++))
        fi
    done
    
    if [ $installed -gt 0 ]; then
        echo -e "\n${GREEN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}${BOLD}  Installation complete!${NC}"
        echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
        echo -e "\n${CYAN}Next steps:${NC}"
        echo "  1. Reload your IDE window (Ctrl+Shift+P → 'Reload Window')"
        echo "  2. Open any .en file"
        echo "  3. The language mode should automatically be 'EC'"
        echo ""
        echo -e "${CYAN}If highlighting doesn't appear:${NC}"
        echo "  - Click the language mode in the bottom-right corner"
        echo "  - Select 'EC' or 'English' from the list"
        echo ""
        echo -e "${CYAN}To test the compiler:${NC}"
        echo "  cd $(dirname "$SCRIPT_DIR")"
        echo "  cargo build --release"
        echo "  ./target/release/ec examples/hello.en --run"
        echo ""
    fi
}

# Uninstall option
uninstall_extension() {
    echo -e "\n${BLUE}${BOLD}Uninstalling EC extension...${NC}"
    
    for ide in "${!IDE_PATHS[@]}"; do
        local target="${IDE_PATHS[$ide]}/ec"
        if [ -L "$target" ] || [ -d "$target" ]; then
            rm -rf "$target"
            echo -e "  ${GREEN}✓${NC} Removed from $ide"
        fi
    done
    
    echo -e "\n${GREEN}Uninstall complete.${NC}"
}

# Show help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --install     Install the extension (default)"
    echo "  --uninstall   Remove the extension from all IDEs"
    echo "  --status      Show installation status"
    echo "  --help        Show this help message"
    echo ""
}

# Show status
show_status() {
    find_ides  # Detect IDEs first
    
    echo -e "\n${BLUE}${BOLD}EC Extension Status${NC}"
    echo ""
    
    if [ ${#IDE_FOUND[@]} -eq 0 ]; then
        echo -e "  ${BLUE}-${NC} No IDEs found"
        echo ""
        return
    fi
    
    for ide in "${!IDE_FOUND[@]}"; do
        local ext_dir="${IDE_PATHS[$ide]}"
        local target="$ext_dir/ec"
        
        if [ -L "$target" ]; then
            local link_target=$(readlink "$target")
            if [ "$link_target" = "$SCRIPT_DIR" ]; then
                echo -e "  ${GREEN}✓${NC} $ide: Installed (symlink)"
            else
                echo -e "  ${YELLOW}⚠${NC} $ide: Symlink points to: $link_target"
            fi
        elif [ -d "$target" ]; then
            echo -e "  ${YELLOW}⚠${NC} $ide: Installed (copy, not symlink)"
        else
            echo -e "  ${RED}✗${NC} $ide: Not installed"
        fi
    done
    echo ""
}

# Main
main() {
    detect_os
    
    case "${1:-}" in
        --uninstall)
            find_ides
            uninstall_extension
            ;;
        --status)
            show_status
            ;;
        --help|-h)
            show_help
            ;;
        --install|"")
            find_ides
            install_extension
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
