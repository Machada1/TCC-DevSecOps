# Dockerfile para imagem customizada do THC-Hydra
FROM alpine:latest
RUN apk add --no-cache hydra
ENTRYPOINT ["hydra"]
