# znode

High-performance proxy server written in Zig. Supports VMess / Trojan / Shadowsocks.

## Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/grrhuipp/znode/main/scripts/install.sh)
```

Specify variant:

```bash
# safe (default, with symbols + runtime checks)
bash <(curl -fsSL https://raw.githubusercontent.com/grrhuipp/znode/main/scripts/install.sh) autobuild safe

# fast (optimized, no symbols)
bash <(curl -fsSL https://raw.githubusercontent.com/grrhuipp/znode/main/scripts/install.sh) autobuild fast

# debug
bash <(curl -fsSL https://raw.githubusercontent.com/grrhuipp/znode/main/scripts/install.sh) autobuild debug

# small (minimal size)
bash <(curl -fsSL https://raw.githubusercontent.com/grrhuipp/znode/main/scripts/install.sh) autobuild small
```

## Config

Default config directory: `/etc/znode/`

## Service

```bash
systemctl status znode
systemctl restart znode
journalctl -u znode -f
```
