# Stage 1: compile the Go binary using the Chainguard Go toolchain image
FROM cgr.dev/chainguard/go:latest AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO_ENABLED=0 produces a static binary that runs on the minimal static base
RUN CGO_ENABLED=0 go build -o /app/server .

# Stage 2: runtime — minimal, no shell, no package manager, runs as nonroot
FROM cgr.dev/chainguard/static:latest
COPY --from=build /app/server /server
EXPOSE 8886
ENTRYPOINT ["/server"]
