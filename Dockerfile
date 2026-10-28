# Two-stage build: the final image holds only the static binary.
# docker build -t vigil .
# Base images are pinned by digest (updated by Dependabot).
# The build stage runs on the build machine and cross-compiles: no emulator
# runs the toolchain for the other architectures.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /vigil ./cmd/vigil \
 && mkdir /data

# Distroless: no shell, no package manager, runs as an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
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
