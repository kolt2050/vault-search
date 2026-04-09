# Vault Scripts

Эта директория содержит Python-скрипты, используемые для инициализации (`seed`) локального Vault, а также для нагрузочного тестирования.

## Нагрузочное тестирование

В проекте есть два контейнера, генерирующих фоновую нагрузку на Vault:
1. `vault-load-tester` (запускает `load_tester.py`)
2. `vault-constant-load` (запускает `constant_load.py`) — создает стабильную целевую нагрузку (по умолчанию ~500 RPS).

### Управление настройками нагрузки

Основное значение целевой нагрузки регулируется в корневом файле `docker-compose.yml`. Для сервиса `vault-constant-load` передаются следующие переменные окружения:

- `TARGET_RPS` — желаемое количество запросов в секунду (по умолчанию установлено на `500`).
- `WORKERS` — количество параллельных воркеров (потоков), выполняющих эти запросы (по умолчанию `50`).

Для изменения нагрузки достаточно исправить `TARGET_RPS` в файле `docker-compose.yml` и пересоздать контейнер одной командой:
```bash
docker-compose up -d vault-constant-load
```

### Как посмотреть текущую нагрузку на Vault (RPS)?

В локальном окружении для Vault включена базовая телеметрия, отдающая метрики в формате Prometheus на эндпоинте `/v1/sys/metrics`. 

**1. Доступ к сырым метрикам**
Вы можете обратиться к HTTP API, чтобы посмотреть общее количество выполненных запросов `vault_core_handle_request_count` (с момента старта):
```bash
curl -s -H "X-Vault-Token: myroot" "http://localhost:8200/v1/sys/metrics?format=prometheus" | grep "vault_core_handle_request_count"
```
*Также метрики включают квантили (0.5, 0.9, 0.99) времени ответа (latency) `vault_core_handle_request`.*

**2. Объединенный мониторинг (RPS + Latency) в реальном времени**
Чтобы наблюдать одновременно и за количеством обрабатываемых запросов в секунду (RPS), и за тем, как быстро Vault на них отвечает (99-й перцентиль задержки), скопируйте и выполните этот скрипт:

```bash
while true; do
  C1=$(curl -s -H "X-Vault-Token: myroot" "http://localhost:8200/v1/sys/metrics?format=prometheus" | grep "^vault_core_handle_request_count" | awk '{print $2}')
  sleep 1
  METRICS=$(curl -s -H "X-Vault-Token: myroot" "http://localhost:8200/v1/sys/metrics?format=prometheus")
  C2=$(echo "$METRICS" | grep "^vault_core_handle_request_count" | awk '{print $2}')
  Q=$(echo "$METRICS" | grep 'vault_core_handle_request{quantile="0.99"}' | awk '{print $2}')
  
  RPS=$(awk "BEGIN {print int($C2 - $C1)}")
  echo -e "RPS: \033[1;32m${RPS}\033[0m | Время ответа (99%): \033[1;33m$Q\033[0m сек"
done
```
Этот цикл будет каждую секунду печатать текущую фактическую нагрузку и скорость обработки медленных запросов. Завершить мониторинг можно через `Ctrl+C`.

### Проверка ресурсов контейнера

Для анализа того, как нагрузка влияет на потребление CPU и памяти самим сервером Vault, используйте:
```bash
docker stats vault-dev
```
