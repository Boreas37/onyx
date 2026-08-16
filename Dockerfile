# Build stage
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /onyx .

# Runtime stage — scratch keeps it minimal; CA certs for the update download
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /onyx /usr/local/bin/onyx
WORKDIR /work
ENTRYPOINT ["onyx"]
