# syntax=docker/dockerfile:1
#
# One image for every goweb deployment. The role (local, provider, or client)
# is chosen at run time with GOWEB_AUTH_MODE; see deploy/ and docs/deployment.md.
# Templates, static assets, translations, and migrations are embedded in the
# binary, so the final image holds only the binary and CA certificates.

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/goweb ./cmd/web

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/goweb /goweb
USER nonroot:nonroot
ENTRYPOINT ["/goweb"]
