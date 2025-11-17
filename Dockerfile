# syntax=docker/dockerfile:1.6

ARG GO_VERSION=1.21

FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src
RUN apk add --no-cache git ca-certificates tzdata
COPY go.mod go.sum* ./ 
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/docker-proxy .

FROM gcr.io/distroless/static-debian12 AS runtime
ENV CUSTOM_DOMAIN="" \
    MODE="production" \
    TARGET_UPSTREAM="https://registry-1.docker.io" \
    LISTEN_ADDR=":8080" \
    REQUEST_TIMEOUT="30s"
COPY --from=builder /out/docker-proxy /usr/local/bin/docker-proxy
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/docker-proxy"]