"# 🛡️ CyberRange MVP

Прототип платформы кибердиапазона с веб-интерфейсом для управления уязвимыми лабораториями.

## 🎯 Возможности

- 📊 **Дашборд** — мониторинг CPU и RAM в реальном времени
- 🐳 **Docker интеграция** — запуск/остановка контейнеров через веб-интерфейс
- 🔗 **Быстрый доступ** — прямая ссылка на запущенную лабораторию
- 🎨 **Красивый UI** — современный дизайн на Bootstrap 5

## 🚀 Быстрый старт

### 1. Установите зависимости

```bash
go mod tidy
```

### 2. Запустите приложение

```bash
go run main.go
```

Сервер запустится на `http://localhost:8080`

### 3. Откройте браузер

Перейдите на http://localhost:8080

## 🐳 Настройка Docker

### Для WSL2 (Windows)

1. Установите Docker Desktop для Windows
2. В настройках Docker Desktop → Settings → Resources → WSL Integration:
   - Включите интеграцию с вашим WSL дистрибутивом
3. Перезапустите WSL: `wsl --shutdown` в PowerShell

### Проверка подключения

```bash
docker ps
```

Если команда работает — всё настроено правильно.

### Права доступа (Linux)

Если видите ошибку `permission denied` для `/var/run/docker.sock`:

**Вариант 1:** Запуск с sudo
```bash
sudo go run main.go
```

**Вариант 2:** Добавить пользователя в группу docker (рекомендуется)
```bash
sudo usermod -aG docker $USER
newgrp docker
# Перелогиньтесь в систему
```

## 📡 API Endpoints

### GET /api/status
Возвращает статистику системы и статус контейнера.

**Пример ответа:**
```json
{
  "system": {
    "cpu": 23.5,
    "ram": 45.2,
    "ram_used_mb": 3680,
    "ram_total_mb": 8192
  },
  "container": {
    "status": "running",
    "ip": "172.17.0.2",
    "port": "8081",
    "url": "http://localhost:8081"
  }
}
```

### POST /api/start
Запускает лабораторию (скачивает образ nginx и запускает контейнер).

**Ответ:**
```json
{
  "message": "🚀 Лаборатория запущена!",
  "url": "http://localhost:8081"
}
```

### POST /api/stop
Останавливает и удаляет контейнер лаборатории.

**Ответ:**
```json
{
  "message": "✅ Контейнер остановлен и удалён"
}
```

## 🛠 Технологии

- **Go 1.23+** — основной язык
- **Gin Gonic** — веб-фреймворк
- **Docker SDK** — управление контейнерами
- **gopsutil** — системные метрики
- **Bootstrap 5** — UI
- **embed** — встраивание HTML в бинарник

## 📂 Структура проекта

```
cyberrange-mvp/
├── main.go              # Весь backend код
├── templates/
│   └── index.html       # Dashboard (встраивается в бинарник)
├── go.mod
└── README.md
```

## 🔧 Конфигурация

В `main.go` можно изменить:

```go
const (
    containerName = "cyberrange-lab"  // Имя контейнера
    imageName     = "nginx:latest"    // Образ (замените на DVWA и т.д.)
    containerPort = "80/tcp"          // Порт внутри контейнера
    hostPort      = "8081"            // Порт на хосте
)
```

## 🎓 Примеры использования

### Запуск DVWA (Damn Vulnerable Web App)

Измените в `main.go`:

```go
const imageName = "vulnerables/web-dvwa"
```

### Запуск нескольких лабораторий

Добавьте параметр scenario в API и динамически выбирайте образ.

## 🐛 Troubleshooting

### Docker не подключается

```bash
# Проверьте что Docker запущен
sudo systemctl status docker

# Перезапустите Docker
sudo systemctl restart docker

# Проверьте сокет
ls -l /var/run/docker.sock
```

### Порт 8081 занят

Измените `hostPort` в `main.go` на другой порт (например, 8082).

### Контейнер не запускается

```bash
# Посмотрите логи контейнера
docker logs cyberrange-lab

# Проверьте что контейнер существует
docker ps -a | grep cyberrange-lab

# Удалите вручную
docker rm -f cyberrange-lab
```

## 📝 Лицензия

MIT

## 🤝 Contributing

PRs welcome! 🚀

</parameter>
</invoke>