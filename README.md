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

### 4. Start Server

```sh
AUTH_ADAPTERS=password mise exec -- gleam run
```

ブラウザで `http://localhost:8080` を開きます。

## Environment Variables

| Variable | Description | Default |
| --- | --- | --- |
| `PORT` | HTTP サーバーの待ち受けポート | `8080` |
| `DATABASE_URL` | PostgreSQL 接続 URL | `postgres://postgres:postgres@localhost:5432/lote` |
| `SECRET_KEY_BASE` | Cookie 署名キー | 起動時にランダム生成 |
| `AUTH_ADAPTERS` | 有効にするログイン方式（カンマ区切り、例: `password`） | 空（すべて無効） |

## Test

```sh
mise exec -- gleam test
```
