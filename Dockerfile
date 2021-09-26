FROM gcr.io/distroless/static

WORKDIR /app

COPY httpproxy ./
ENTRYPOINT ["/app/httpproxy"]
