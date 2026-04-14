# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.25 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0

RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /out/sni-spoofing .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iptables && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/sni-spoofing /usr/local/bin/sni-spoofing

ENTRYPOINT ["/usr/local/bin/sni-spoofing"]

