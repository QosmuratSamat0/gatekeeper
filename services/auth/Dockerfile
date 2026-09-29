# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /src

# Download dependencies first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -trimpath \
    -o /bin/auth \
    ./cmd/auth

# Production stage: distroless static nonroot
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /bin/auth /app/auth

USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/app/auth"]
