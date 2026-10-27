# Two-stage build: the final image holds only the static binary.
# docker build -t vigil .
FROM golang:1.27-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /vigil ./cmd/vigil \
 && mkdir /data

# Distroless: no shell, no package manager, runs as an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /vigil /usr/local/bin/vigil
COPY --from=build --chown=nonroot:nonroot /data /data
ENV VIGIL_DB=/data/vigil.db
VOLUME /data
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/vigil"]
# Inside a container the UI must listen on every interface; TLS is expected to
# be terminated by a reverse proxy (or use -tls-cert/-tls-key instead).
CMD ["serve", "-addr", "0.0.0.0:8080", "-behind-proxy"]
