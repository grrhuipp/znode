# znode 项目指南

## 语言要求
- 所有回答必须使用**中文**

## 项目概述
用 Zig 重写 C++23 高性能代理服务器 (d:\cnode → d:\znode)，消除抽象成本（虚函数、堆分配、模板膨胀）。

支持协议：VMess / Trojan / Shadowsocks
平台：仅 Linux

## 技术栈
- **Zig 0.15.2**
- **zio v0.9.0** — Go 风格 stackful 协程，io_uring 后端
- **aws-lc** — TLS + 加密（@cImport 绑定，cmake 编译）

## 核心设计原则
1. **comptime 泛型替代虚函数** — `TlsStream(comptime Inner)` 按值存储，零堆分配
2. **tagged union 替代 vtable** — `TransportStream = union(enum) { tcp, tcp_tls, tcp_ws, tcp_tls_ws }` + `inline else`
3. **SessionContext 数据总线** — 各层只读写自己的字段，零跨层耦合
4. **固定缓冲区替代堆分配** — TargetAddress 用 `[253]u8`，SessionContext 全栈分配
5. **原子指针交换替代 shared_ptr** — RCU 用户存储

## 构建
```bash
# 基础构建（不含 TLS/加密）
zig build -Dtarget=x86_64-linux

# 含 aws-lc（需要 cmake + ninja）
zig build -Dtarget=x86_64-linux -Dawslc=true

# 先编译 aws-lc
zig build awslc-build
```

## 目录结构
```
src/
  main.zig              入口
  types.zig             ErrorCode, TargetAddress, Protocol, ConnState, defaults
  config.zig            JSON 配置解析（支持 PascalCase/camelCase）
  log.zig               多通道日志（app/access/error + console）
  mem/buffer.zig        Buffer(8KB) + MultiBuffer + Pool
  app/session.zig       SessionContext 数据总线
  protocol/trojan.zig   Trojan 协议解析
  router.zig            域名后缀 + IP CIDR 路由
  outbound/manager.zig  出站管理（freedom/blackhole）
  runtime/server.zig    TCP 监听 + 连接处理（待迁移到 zio）
  runtime/stats.zig     原子统计（待改为 cache-line 对齐分片）
```

## 实现计划（10 阶段）
详见：`C:\Users\Administrator\.claude\plans\humming-beaming-yeti.md`

已完成：Phase 1（项目骨架 + 基础类型）
下一步：Phase 2（加密层 — aws-lc 封装）

## C++ 参考源码
- `d:\cnode\` — 原始 C++23 实现（~20K 行）
- 关键文件映射见计划文件

## 编码规范
- Zig 命名：snake_case 函数/变量，PascalCase 类型
- 错误处理：`!` 返回错误，热路径不 panic
- 内存：优先 arena/栈分配，避免 GPA 热路径
- 日志中文标注模块名，如 `std.log.info("监听启动: ...")`
- Zig 0.15.2 的 `{f}` 格式化调用 `format(writer)` 只传 1 个参数（非旧版 3 参数签名）
