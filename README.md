# lote

Gleam + PostgreSQL + Lustre Server Components (WebSocket) で作るリアルタイム micropost アプリ。

## Stack

- **Language / Runtime**: Gleam (Erlang/BEAM)
- **Web / WebSocket**: Mist + Wisp + Lustre Server Components
- **Database**: PostgreSQL 18 (`pog` + `cake` / `cake_pog` + `cigogne`)
- **Auth**: Session Cookie (PostgreSQL) + Argon2id (`argus`)

## Local Development

### Prerequisites

- [mise](https://mise.jdx.dev/)（[mise.toml](mise.toml) で Erlang / Gleam バージョンを管理）
- Docker / Docker Compose

### 1. Start PostgreSQL

```sh
docker compose up -d
```

### 2. Run Migrations

```sh
DATABASE_URL=postgres://postgres:postgres@localhost:5432/lote \
  mise exec -- gleam run -m cigogne -- all
```

### 3. Seed Development Users

`alice` / `bob`（パスワード: `password1234`）を作成します（冪等）。

```sh
mise exec -- gleam run -m lote/seed
```

### 4. Build CSS (Tailwind)

```sh
mise exec -- gleam run -m lustre/dev add tailwind
.lustre/bin/tailwindcss-linux-x64/tailwindcss-linux-x64 -i src/lote.css -o priv/static/app.css --minify
```

### 5. Start Server

```sh
AUTH_ADAPTERS=password mise exec -- gleam run
```

ブラウザで `http://localhost:8080` を開きます。

## Environment Variables

| Variable | Description | Default |
| --- | --- | --- |
| `PORT` | HTTP サーバーの待ち受けポート（`1..65535`） | `8080` |
| `DATABASE_URL` | PostgreSQL 接続 URL | `postgres://postgres:postgres@localhost:5432/lote` |
| `SECRET_KEY_BASE` | Cookie 署名キー（64 バイト以上、`https://` Issuer 時は必須） | `http://` 時のみ起動時にランダム生成 |
| `ISSUER_URL` | OAuth 2.0 / OIDC Issuer URL（兼デフォルト API Audience、不正値は起動エラー） | `http://localhost:<PORT>` |
| `OIDC_SIGNING_KEY_PEM` | ES256 `id_token` 署名用 EC P-256 秘密鍵 PEM（`https://` Issuer 時は必須） | `http://` 時のみ起動時にエフェメラル生成 |
| `OIDC_VERIFY_KEYS_PEM` | 鍵ローテーション中の旧 EC P-256 公開鍵 PEM バンドル | 空（なし） |
| `AUTH_ADAPTERS` | 有効にするログイン方式（カンマ区切り、例: `password`） | 空（すべて無効） |
| `PUBSUB_ADAPTER` | PubSub バックエンド（`memory` または `postgres`） | `memory` |
| `RATE_LIMIT_ADAPTER` | レートリミットバックエンド（`memory` または `postgres`） | `PUBSUB_ADAPTER` と同じ |
| `TRUSTED_PROXY_HOPS` | 信頼するリバースプロキシの段数（`X-Forwarded-For` 解決用） | `0` |

## Test

```sh
mise exec -- gleam test
```
