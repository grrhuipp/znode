FROM alpine:latest

COPY zig-out/bin/znode /usr/local/bin/znode

VOLUME ["/etc/znode"]

EXPOSE 443 8080

ENTRYPOINT ["/usr/local/bin/znode", "-d", "/etc/znode"]
