# syntax=docker/dockerfile:1

FROM ghcr.io/gleam-lang/gleam:v1.19.2-erlang AS builder

WORKDIR /build

COPY gleam.toml manifest.toml ./
RUN gleam deps download

COPY src ./src
COPY priv ./priv

RUN gleam run -m lustre/dev add tailwind \
    && mkdir -p priv/static \
    && .lustre/bin/tailwindcss-*/tailwindcss-* -i src/lote.css -o priv/static/app.css --minify \
    && gleam export erlang-shipment

FROM erlang:29.1.3-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system app && useradd --system --gid app app

WORKDIR /app
COPY --from=builder --chown=app:app /build/build/erlang-shipment ./

USER app

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["run"]
