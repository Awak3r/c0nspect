# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
# Keep modules in an ordinary layer: the GHA layer exporter preserves it.
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
# CI injects/extracts this mount with buildkit-cache-dance; GHA alone does not.
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags="-s -w" -o /out/conspect ./cmd/conspect

FROM alpine:3.23 AS runtime
RUN apk add --no-cache ca-certificates tar \
    && addgroup -S -g 10001 conspect \
    && adduser -S -D -H -u 10001 -G conspect conspect \
    && mkdir -p /data/uploads \
    && chown -R 10001:10001 /data
COPY --from=build /out/conspect /usr/local/bin/conspect
WORKDIR /data
ENV APP_ADDR=:8080 DATA_DIR=/data
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["wget", "--quiet", "--spider", "http://127.0.0.1:8080/healthz"]
ENTRYPOINT ["/usr/local/bin/conspect"]
