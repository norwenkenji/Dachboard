# Провайдеры туннеля

`config.yaml → tunnel.provider` — любой исполняемый файл. Дашборд запускает
его, забирает **первый `http(s)://…` URL** из stdout, кеширует
(`tunnel.cache_seconds`) и отдает в `GET /api/tunnel`.
Если провайдер молчит — отдается `tunnel.cache_file`.

В комплекте:

| скрипт | назначение |
|---|---|
| `tunnel/providers/cloudflared-quick.sh [container]` | URL `*.trycloudflare.com` из `docker logs` (плавающие туннели) |
| `tunnel/providers/static.sh <file>` | URL из файла (именные туннели, руками) |
| `tunnel/providers/ngrok.sh [api-base]` | URL из локального API агента `:4040` |

Свой под что угодно:

```sh
#!/bin/sh
# my-provider.sh — печатает ровно один URL
curl -s http://127.0.0.1:4040/api/tunnels | grep -Eo 'https://[^"]+'
```

Затем укажи его в `tunnel.provider`.
