# Stage 1: Build frontend
FROM node:20-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Stage 2: Build Go binary
FROM golang:1.22-alpine AS backend
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /app/frontend/build ./frontend/build
RUN CGO_ENABLED=1 go build -o passwd-server ./cmd/passwd-server
RUN CGO_ENABLED=1 go build -o passwd ./cmd/passwd
RUN CGO_ENABLED=1 go build -o passwd-mcp ./cmd/passwd-mcp

# Stage 3: Runtime
FROM alpine:3.19
RUN apk add --no-cache libc6-compat
WORKDIR /app
COPY --from=backend /app/passwd-server .
COPY --from=backend /app/passwd .
COPY --from=backend /app/passwd-mcp .
EXPOSE 8080
CMD ["./passwd-server"]
# PORT env var is read by the server at runtime (Render.com sets it)
