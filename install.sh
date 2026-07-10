#!/bin/bash
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}  XIAO  IP-Reality v2.0  一键安装${NC}"
echo -e "${CYAN}================================================${NC}"
echo

INSTALL_DIR="/opt/ip-reality"
BIN_PATH="/usr/local/bin/xiao"
REPO_URL="https://github.com/yu-929/IP-Reality.git"

# 1. 检查 Python
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[FAIL] 需要 Python 3.10+，请先安装${NC}"
    exit 1
fi
PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${GREEN}[OK]${NC} Python $PYVER"

# 2. 安装依赖
echo -e "${CYAN}[..] 安装 Python 依赖 ...${NC}"
pip3 install --break-system-packages cryptography aiodns colorama aiohttp 2>/dev/null || \
pip3 install cryptography aiodns colorama aiohttp 2>/dev/null || true

# 3. 克隆/更新项目
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${CYAN}[..] 更新已有项目 ...${NC}"
    cd "$INSTALL_DIR" && git pull --ff-only 2>/dev/null || true
else
    echo -e "${CYAN}[..] 克隆项目 ...${NC}"
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

# 4. 安装为包 (pip install -e)
echo -e "${CYAN}[..] 注册全局命令 ...${NC}"
cd "$INSTALL_DIR"
pip3 install --break-system-packages -e . 2>/dev/null || pip3 install -e . 2>/dev/null || {
    # 降级: 手动创建 wrapper
    cat > "$BIN_PATH" << 'CMDE'
#!/bin/bash
cd /opt/ip-reality && exec python3 -m src.cli "$@"
CMDE
    chmod +x "$BIN_PATH"
}

echo
echo -e "${GREEN}[OK] 安装完成！${NC}"
echo
echo -e "  快速开始:"
echo -e "    ${CYAN}xiao --sni images.apple.com --cf-domain your.domain.com${NC}"
echo
echo -e "  菜单模式:"
echo -e "    ${CYAN}xiao${NC}"
echo
echo -e "  更新:"
echo -e "    ${CYAN}curl -fsSL https://raw.githubusercontent.com/e13815332/ip-reality/main/install.sh | bash${NC}"
