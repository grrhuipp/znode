#!/bin/bash
set -euo pipefail

# znode 一键安装/更新脚本
# 用法: curl -fsSL https://raw.githubusercontent.com/grrhuipp/znode/main/scripts/install.sh | bash
# 参数: [版本] [变体]
#   版本: autobuild (默认), v1.0.0, ...
#   变体: safe (默认,带符号), fast, debug, small

REPO="grrhuipp/znode"
INSTALL_DIR="/opt/znode"
SERVICE_NAME="znode"
CONFIG_DIR="/opt/znode"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# 检测架构（仅支持 x86_64）
detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)  echo "amd64" ;;
        *) error "不支持的架构: $arch（仅支持 x86_64）" ;;
    esac
}

# 下载并安装
install_binary() {
    local version=$1
    local arch=$2
    local variant=$3
    local artifact="znode-linux-${arch}-${variant}"
    local url="https://github.com/${REPO}/releases/download/${version}/${artifact}.tar.gz"

    info "下载 ${version} (${arch})..."
    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf $tmpdir" EXIT

    curl -fsSL "$url" -o "${tmpdir}/${artifact}.tar.gz" || error "下载失败: $url"
    tar xzf "${tmpdir}/${artifact}.tar.gz" -C "$tmpdir"

    sudo mkdir -p "${INSTALL_DIR}"
    info "安装到 ${INSTALL_DIR}/znode..."
    sudo install -m 755 "${tmpdir}/${artifact}" "${INSTALL_DIR}/znode"
}

# 创建默认配置
setup_config() {
    if [ -d "$CONFIG_DIR" ]; then
        warn "配置目录已存在: ${CONFIG_DIR}，跳过"
        return
    fi

    info "创建配置目录 ${CONFIG_DIR}..."
    sudo mkdir -p "$CONFIG_DIR"

    # 最小配置
    sudo tee "${CONFIG_DIR}/config.json" > /dev/null << 'CONF'
{
  "Workers": 0,
  "Log": {
    "level": "info",
    "output": "/opt/znode/log"
  },
  "Dns": {
    "servers": ["8.8.8.8", "1.1.1.1"]
  }
}
CONF

    sudo tee "${CONFIG_DIR}/inbound.json" > /dev/null << 'CONF'
[]
CONF

    sudo tee "${CONFIG_DIR}/outbound.json" > /dev/null << 'CONF'
[
  {"tag": "direct", "protocol": "freedom"},
  {"tag": "blackhole", "protocol": "blackhole"}
]
CONF

    sudo tee "${CONFIG_DIR}/route.json" > /dev/null << 'CONF'
{"rules": []}
CONF

    info "默认配置已写入，请编辑 ${CONFIG_DIR}/ 下的文件"
}

# 安装 systemd 服务
setup_service() {
    local service_file="/etc/systemd/system/${SERVICE_NAME}.service"

    if [ -f "$service_file" ]; then
        warn "服务文件已存在，跳过创建"
    else
        info "创建 systemd 服务..."
        sudo tee "$service_file" > /dev/null << UNIT
[Unit]
Description=znode proxy service
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/znode -c ${CONFIG_DIR}
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
        sudo systemctl daemon-reload
        sudo systemctl enable "$SERVICE_NAME"
    fi
}

# 主流程
main() {
    info "=== znode 安装/更新 ==="

    # 检查 root 或 sudo
    if [ "$(id -u)" -ne 0 ] && ! command -v sudo &>/dev/null; then
        error "需要 root 权限或安装 sudo"
    fi

    local arch
    arch=$(detect_arch)

    local version="${1:-autobuild}"
    local variant="${2:-safe}"
    info "目标版本: ${version} (${variant})"

    # 检查是否已安装相同版本
    if command -v znode &>/dev/null; then
        local current
        current=$(znode --version 2>/dev/null || echo "unknown")
        info "当前版本: ${current}"
    fi

    # 停止服务（如果正在运行）
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "停止 ${SERVICE_NAME} 服务..."
        sudo systemctl stop "$SERVICE_NAME"
    fi

    install_binary "$version" "$arch" "$variant"
    setup_config
    setup_service

    # 启动服务
    info "启动 ${SERVICE_NAME} 服务..."
    sudo systemctl start "$SERVICE_NAME"

    info "=== 安装完成 ==="
    info "二进制: ${INSTALL_DIR}/znode"
    info "配置:   ${CONFIG_DIR}/"
    info "日志:   journalctl -u ${SERVICE_NAME} -f"
    info "状态:   systemctl status ${SERVICE_NAME}"
}

main "$@"
