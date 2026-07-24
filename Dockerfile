FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /out/mincloud ./cmd/mincloud

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/mincloud /mincloud
EXPOSE 9900
ENTRYPOINT ["/mincloud"]
