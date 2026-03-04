/// Outbound registry — manages all outbound protocols including proxy outbounds.
///
/// Supports: freedom, blackhole, trojan, vmess, shadowsocks.
const std = @import("std");
const config = @import("../infra/config.zig");
const trojan_outbound = @import("../protocol/trojan/outbound.zig");
const vmess_outbound = @import("../protocol/vmess/outbound.zig");
const ss_outbound = @import("../protocol/shadowsocks/outbound.zig");

pub const OutboundKind = enum {
    freedom,
    blackhole,
    trojan,
    vmess,
    shadowsocks,
};

pub const ProtoConfig = union(enum) {
    none: void,
    trojan: trojan_outbound.TrojanOutbound,
    vmess: vmess_outbound.VMessOutbound,
    ss: ss_outbound.SsOutbound,
};

pub const Outbound = struct {
    tag: []const u8,
    kind: OutboundKind,
    address: []const u8,
    port: u16,
    stream_settings: config.StreamSettings,
    proto: ProtoConfig,
};

pub const Manager = struct {
    outbounds: []const Outbound,

    pub fn init(allocator: std.mem.Allocator, cfg: []const config.OutboundConfig) !Manager {
        var list = std.array_list.Managed(Outbound).init(allocator);

        for (cfg) |item| {
            const kind = parseKind(item.protocol) orelse {
                std.log.warn("忽略未知出站协议: tag={s} protocol={s}", .{ item.tag, item.protocol });
                continue;
            };

            var proto: ProtoConfig = .{ .none = {} };

            switch (kind) {
                .trojan => {
                    if (item.password.len > 0) {
                        proto = .{ .trojan = trojan_outbound.TrojanOutbound.init(item.password) };
                    }
                },
                .vmess => {
                    if (item.uuid.len > 0) {
                        if (vmess_outbound.VMessOutbound.init(item.uuid, item.security)) |v| {
                            proto = .{ .vmess = v };
                        } else {
                            std.log.warn("无效VMess UUID: tag={s}", .{item.tag});
                            continue;
                        }
                    }
                },
                .shadowsocks => {
                    if (item.password.len > 0) {
                        const method = if (item.method.len > 0) item.method else "aes-128-gcm";
                        if (ss_outbound.SsOutbound.init(item.password, method)) |s| {
                            proto = .{ .ss = s };
                        } else {
                            std.log.warn("无效SS配置: tag={s}", .{item.tag});
                            continue;
                        }
                    }
                },
                else => {},
            }

            try list.append(.{
                .tag = item.tag,
                .kind = kind,
                .address = item.address,
                .port = item.port,
                .stream_settings = item.stream_settings,
                .proto = proto,
            });
        }

        return .{
            .outbounds = try list.toOwnedSlice(),
        };
    }

    pub fn find(self: *const Manager, tag: []const u8) ?Outbound {
        for (self.outbounds) |item| {
            if (std.mem.eql(u8, item.tag, tag)) return item;
        }
        return null;
    }
};

fn parseKind(protocol: []const u8) ?OutboundKind {
    if (std.ascii.eqlIgnoreCase(protocol, "freedom") or
        std.ascii.eqlIgnoreCase(protocol, "direct")) return .freedom;
    if (std.ascii.eqlIgnoreCase(protocol, "blackhole")) return .blackhole;
    if (std.ascii.eqlIgnoreCase(protocol, "trojan")) return .trojan;
    if (std.ascii.eqlIgnoreCase(protocol, "vmess")) return .vmess;
    if (std.ascii.eqlIgnoreCase(protocol, "shadowsocks") or
        std.ascii.eqlIgnoreCase(protocol, "ss")) return .shadowsocks;
    return null;
}
