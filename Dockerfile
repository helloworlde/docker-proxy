# syntax=docker/dockerfile:1.6

ARG GO_VERSION=1.21

FROM golang:${GO_VERSION}-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
WORKDIR /src
RUN apk add --no-cache git ca-certificates tzdata
COPY go.mod go.sum* ./ 
RUN go mod download
COPY . .
RUN set -eux; \
    TARGET_OS="${TARGETOS:-linux}"; \
    TARGET_ARCH="${TARGETARCH:-amd64}"; \
    if [ "${TARGET_ARCH}" = "arm" ] && [ -n "${TARGETVARIANT}" ]; then \
        export GOARM="${TARGETVARIANT#v}"; \
    fi; \
    CGO_ENABLED=0 GOOS="${TARGET_OS}" GOARCH="${TARGET_ARCH}" \
        go build -trimpath -ldflags="-s -w" -o /out/docker-proxy .

FROM gcr.io/distroless/static-debian12 AS runtime
ENV CUSTOM_DOMAIN="" \
    LISTEN_ADDR=":8080" \
    REQUEST_TIMEOUT="30s"
COPY --from=builder /out/docker-proxy /usr/local/bin/docker-proxy
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/docker-proxy"]