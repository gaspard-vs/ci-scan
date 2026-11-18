# The detection image. go-enry has no published image, so CI scan builds one
# from fixed inputs: the Go image by digest, go-enry by go.sum.

# golang:1.27.4-alpine
FROM golang@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /detection .

FROM scratch
COPY --from=build /detection /detection
ENTRYPOINT ["/detection"]
