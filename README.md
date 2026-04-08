# Утилита для поиска в HashiCorp Vault
## Запуск vault с тестовыми данными:
```
docker compose -f docker-compose.vault.yml up -d
```

## Запуск поисковой утилиты:

```bash
# VAULT_TOKEN=myroot (для тестового волта)
# VAULT_ADDR=http://host.docker.internal:8200/ - это адрес Vault-сервера который запущен рядом для теста
docker compose -f docker-compose.app.yml run --rm \
  -e VAULT_ADDR=http://host.docker.internal:8200/ \
  -e VAULT_TOKEN=токен \
  vault-search "что_ищем" 

# Ищем только в путях
docker compose -f docker-compose.app.yml run --rm \
  -e VAULT_ADDR=http://host.docker.internal:8200/ \
  -e VAULT_TOKEN=токен \
  vault-search "что_ищем" --mode path

# Ищем только во внутренних ключах
docker compose -f docker-compose.app.yml run --rm \
  -e VAULT_ADDR=http://host.docker.internal:8200/ \
  -e VAULT_TOKEN=токен \
  vault-search "что_ищем" --mode keys

# Ищем пустые секреты
docker compose -f docker-compose.app.yml run --rm \
  -e VAULT_ADDR=http://host.docker.internal:8200/ \
  -e VAULT_TOKEN=токен \
  vault-search --empty
```
