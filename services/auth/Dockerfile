# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /src

# Download dependencies first for better layer caching.
# If dependencies haven't changed, Docker reuses this layer without re-downloading.
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Target OS and architecture arguments populated automatically by Docker Buildx.
# Default to linux/amd64 if built without buildx so single-platform local builds succeed.
# This prevents compilation failure on ARM64 nodes (e.g. Apple Silicon, AWS Graviton).
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
    -ldflags="-s -w" \
    -trimpath \
    -o /bin/auth \
    ./cmd/api

# Production stage: distroless static nonroot.
# Distroless contains only the application binary and CA certificates without a package manager
# or shell, minimizing the attack surface.
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /bin/auth /app/auth

USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/app/auth"]
