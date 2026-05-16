# Multi-stage build. Placeholder — the real image is produced at the
# v0.1.0 milestone. This file exists so contributors can see the
# intended shape and the CI can wire image-build smoke tests against
# it incrementally.

ARG GO_VERSION=1.23

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
ARG VERSION=0.0.0-dev
RUN CGO_ENABLED=0 go build \
      -ldflags "-s -w -X main.Version=${VERSION}" \
      -o /out/aegrail-engine \
      ./cmd/aegrail-engine \
 && CGO_ENABLED=0 go build \
      -ldflags "-s -w -X main.Version=${VERSION}" \
      -o /out/aegrail-webhook \
      ./cmd/aegrail-webhook

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/aegrail-engine /aegrail-engine
COPY --from=build /out/aegrail-webhook /aegrail-webhook
USER nonroot:nonroot
EXPOSE 8080
# Default ENTRYPOINT is the proxy; webhook Deployments override
# command to ["/aegrail-webhook"] in their pod spec.
ENTRYPOINT ["/aegrail-engine"]
