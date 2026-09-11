# Dachboard — русская документация

Самостоятельная панель для своего сервера. Один демон, один туннель,
права на пользователя.

- **Обзор** — CPU / RAM / диск / температуры / нагрузка, статусы сервисов и контейнеров
- **Службы** — `docker ps` + systemd-юниты, стрим логов, старт/стоп/рестарт (по праву)
- **Консоль** — проверенные команды-пресеты и живой шелл ([ttyd](https://github.com/tsl0922/ttyd)) в своем слоте
- **Файлы** — менеджер, замкнутый на домашнюю папку пользователя
- **Туннель** — текущий публичный URL через generic-провайдер
- **Пользователи** — аккаунты, матрица прав, лимиты CPU/RAM/диска, API-токены

Слушает только `127.0.0.1`. Наружу — через свой туннель (Cloudflare, playit, …)
и/или nginx. Порт светить нельзя.

## Быстрый старт (сервер, Ubuntu/Debian, root, python 3.10+)

```bash
git clone https://github.com/norwenkenji/Dachboard.git /root/dachboard-src
cd /root/dachboard-src
sudo bash deploy/install.sh
sudo systemctl start dachboard.service
# одноразовый setup-токен (сгорает после использования):
sudo journalctl -u dachboard -n 5 | grep "SETUP TOKEN"
# открыть http://127.0.0.1:8420 → карточка first-setup → создать админа
```

Туннель наружу: [docs/TUNNEL.ru.md](TUNNEL.ru.md).

Дальше: вкладка Users — создать пользователя (логин + временный пароль +
слот `u-c1`… + галочки прав + лимиты). Свой пароль ставит сам при первом
входе. Ссылку на туннель и доступы раздай любым способом (тг-бот, QR, …) —
эта интеграция специально вне репозитория.

## Туннель для любого кода

Без сессии — API-токен из UI (Users → api tokens, скоуп `tunnel_view`;
показывается один раз, отзыв, видно последнее использование):

```bash
curl -H "Authorization: Bearer dach_..." https://<tunnel>/api/tunnel
# {"url": "https://xxx.trycloudflare.com"}
```

## Модель безопасности

- Дефолтных паролей нет, секретов в репо и `.env` нет.
- **Bootstrap**: при первом старте без админа демон генерит одноразовый
  setup-токен (файл `0600` в data, плюс в journal). `POST /api/setup` с ним
  создает первого админа и **сжигает** токен. Дальше endpoint отдает 404.
- **Предрегистрация**: админ создает юзера с временным паролем и флагом
  смены. Первый логин отклоняется, пока юзер не задаст свой пароль через
  `POST /api/first-password`. Временный умирает сразу.
- Пароли: scrypt. Сессии: случайные токены, expiry, `HttpOnly` куки.
- Команды — только argv-массивами, без шелла, от имени юзера через `runuser`
  (опционально в `systemd-run` слайсе с лимитами).
- Терминалы слушают loopback; nginx пускает через `auth_request` по сессии
  дашборда + праву `terminal` + совпадению слота.
- Жесткие квоты диска — через ext4 usrquota автоматом из `install.sh`
  (на других ФС — предупреждение + мягкий режим).

## Обновление

```bash
cd /root/dachboard-src && git pull && sudo bash deploy/install.sh
sudo systemctl restart dachboard.service
```

## Структура

```
app/            демон FastAPI (auth, rbac, metrics, runner, files, tunnel)
static/         SPA на чистом JS, без сборки
tunnel/         провайдеры (исполняемый файл печатает URL)
deploy/         install.sh, systemd-юниты, nginx-сниппет, tunnel-setup.py
docs/           документация (EN + RU)
tests/          pytest, 60+ тестов
```

## Лицензия

MIT.
