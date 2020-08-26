FROM gcr.io/moonrhythm-containers/alpine:3.12

RUN mkdir -p /app
WORKDIR /app

COPY httpproxy ./
ENTRYPOINT ["/app/httpproxy"]
