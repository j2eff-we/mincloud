# Build a static mincloud binary, then ship it on a minimal base.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/mincloud ./cmd/mincloud

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mincloud /usr/local/bin/mincloud
EXPOSE 9900 9910
ENTRYPOINT ["/usr/local/bin/mincloud"]
