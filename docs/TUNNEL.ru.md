# TUNNEL.ru — вывод dachboard в интернет бесплатно

Дашборд слушает только `127.0.0.1`. Чтобы показать его людям, нужен туннель.
Подойдет любой: укажи `tunnel.provider` в `config.yaml` на скрипт, который
печатает публичный URL, и дашборд отдаст его в `GET /api/tunnel`
(с кешем + файл-фолбэк для внешних ботов).

## Вариант A: cloudflared quick (проще всего, без аккаунта, URL плавает)

```bash
python3 deploy/tunnel-setup.py quick
# -> https://xxx.trycloudflare.com
```

Дефолтный конфиг уже читает логи этого контейнера
(`tunnel/providers/cloudflared-quick.sh dachboard-tunnel`).
Минус: URL меняется при каждом пересоздании контейнера — перерасшаривай
ссылку. Бот-раздатчик пусть опрашивает `GET /api/tunnel` и пересылает свежий
URL. Полностью автоматизировано, кредов не надо.

## Вариант B: cloudflared named (стабильный поддомен, бесплатный аккаунт)

Нужен API-токен Cloudflare (Tunnel:Edit + DNS:Edit) и домен на Cloudflare.
Браузер не нужен — всё через API:

```bash
python3 deploy/tunnel-setup.py named --cf-token $CF_TOKEN --host dash.example.com
# -> стабильный URL: https://dash.example.com
```

Создаст туннель, пропишет DNS CNAME и запустит коннектор.
Затем переключи провайдер дашборда на стабильный URL:

```yaml
tunnel:
  provider: tunnel/providers/static.sh
  args: [/opt/dachboard/data/my-url.txt]
```

```bash
echo https://dash.example.com > /opt/dachboard/data/my-url.txt
```

Нюанс: зона `--host` по умолчанию — последние два лейбла; для экзотических
TLD передай `--zone` явно (`--host a.dash.example.co.uk --zone example.co.uk`).

## Вариант C: ngrok (условно-стабильный URL, токен из кабинета ngrok)

```bash
python3 deploy/tunnel-setup.py ngrok --token $NGROK_TOKEN
```

Провайдер: `tunnel/providers/ngrok.sh` (читает локальный API `:4040`).

## Вариант D: playit / tailscale funnel (ручной клейм)

Там клейм агента только через браузер/клик — не скриптуется. Натрави их
агента на `127.0.0.1:80`, дальше `static.sh` или свой провайдер из 5 строк
(см. `docs/PROVIDERS.ru.md`).

## Заметки

- HTTPS терминирует провайдер туннеля. `cookie_secure: true` не трогай.
- Сырой порт не публикуй. Модель угроз — только loopback.
- Quick-URL публичны по обскурности: реальные ворота — стена логина.
  Пароли от 12 символов (для админа setup требует принудительно).
