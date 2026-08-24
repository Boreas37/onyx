# P3-18a — multi-stage scratch image.
#
# Stage 1 builds the static (CGO-free) onyx binary; the same stage also
# installs ca-certificates so the standard bundle can be copied into the
# scratch runtime (TLS must work for the database update download).
#
# Build args feed main.buildCommit / main.buildTime into -ldflags; both
# default so a plain `docker build` works without them.
FROM golang:1.23-alpine AS build
ARG BUILD_COMMIT=unknown
ARG BUILD_TIME=unknown
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.buildCommit=${BUILD_COMMIT} -X main.buildTime=${BUILD_TIME}" \
    -o /out/onyx .

# Runtime stage — scratch: minimal attack surface, no shell, no package manager.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/onyx /onyx
WORKDIR /data
ENTRYPOINT ["/onyx"]
