# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /rokmail .

# Runs as root on purpose: it owns the shared /db and /dkim volumes and creates
# files world-readable (umask 0) for the mail and rspamd containers.
FROM gcr.io/distroless/static-debian12
COPY --from=build /rokmail /rokmail
EXPOSE 8080
ENTRYPOINT ["/rokmail"]
CMD ["serve"]
