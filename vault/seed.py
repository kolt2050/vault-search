"""
Скрипт для наполнения Vault тестовыми данными.
Запускается как init-контейнер при старте Vault.
Ожидает готовности Vault, затем загружает данные из seed_data.json.
"""
import os
import sys
import json
import time
import hvac

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault-dev:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "myroot")
SEED_FILE = os.path.join(os.path.dirname(__file__), "seed_data.json")

INIT_FILE = "/vault/file/init.json"

MAX_RETRIES = 30
RETRY_INTERVAL = 2

def wait_for_vault(client: hvac.Client):
    """Ожидает, пока Vault станет доступен по HTTP."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            client.sys.is_initialized()
            print(f"[seed] Vault доступен (HTTP отвечает, попытка {attempt})")
            return
        except Exception as e:
            pass
        print(f"[seed] Vault ещё не отвечает по HTTP, ждём {RETRY_INTERVAL}с... (попытка {attempt}/{MAX_RETRIES})")
        time.sleep(RETRY_INTERVAL)

    print("[seed] ОШИБКА: Vault не стал доступен за отведённое время.")
    sys.exit(1)


def init_and_unseal(client: hvac.Client):
    """Инициализирует и/или распечатывает Vault."""
    if not client.sys.is_initialized():
        print("[seed] Vault не инициализирован. Выполняю инициализацию...")
        result = client.sys.initialize(secret_shares=1, secret_threshold=1)
        init_data = {
            "root_token": result["root_token"],
            "keys": result["keys"]
        }
        with open(INIT_FILE, "w", encoding="utf-8") as f:
            json.dump(init_data, f)
        print("[seed] Vault успешно инициализирован. Ключи сохранены на диске.")
    
    if os.path.exists(INIT_FILE):
        with open(INIT_FILE, "r", encoding="utf-8") as f:
            init_data = json.load(f)
    else:
        print(f"[seed] ОШИБКА: Секреты инициализации ({INIT_FILE}) не найдены!")
        sys.exit(1)

    if client.sys.is_sealed():
        print("[seed] Vault запечатан. Выполняю распечатывание (unseal)...")
        client.sys.submit_unseal_keys(keys=[init_data["keys"][0]])
        print("[seed] Vault успешно распечатан.")

    # Выставляем правильный root токен, чтобы скрипт мог работать
    client.token = init_data["root_token"]

    if not client.is_authenticated():
        print("[seed] ОШИБКА: Не удалось аутентифицироваться с помощью root токена.")
        sys.exit(1)

    # Убеждаемся, что существует фиксированный токен myroot, который требует скрипт поиска (vault_search.py)
    try:
        # Проверяем, жив ли такой токен:
        client.auth.token.lookup(token="myroot")
        print("[seed] Дефолтный токен 'myroot' уже существует и активен.")
    except Exception:
        print("[seed] Дефолтный токен 'myroot' не найден/не активен. Создаю/обновляю новый токен 'myroot'...")
        try:
            client.auth.token.create(id="myroot", policies=["root"])
            print("[seed] Токен 'myroot' успешно создан.")
        except Exception as e:
            # Предупреждение о SHA1 считается нормой (hvac.exceptions.InvalidRequest и т.д.)
            if "duplicate ID" in str(e):
                pass
            elif "SHA1" in str(e):
                pass
            else:
                print(f"[seed] Внимание: при создании токена 'myroot': {e}")


def seed(client: hvac.Client):
    if not os.path.exists(SEED_FILE):
        print(f"[seed] Файл с тестовыми данными не найден: {SEED_FILE}")
        sys.exit(1)

    with open(SEED_FILE, "r", encoding="utf-8") as f:
        seed_data = json.load(f)

    for engine, secrets in seed_data.items():
        # Включаем движок KV v2
        try:
            client.sys.enable_secrets_engine(
                backend_type="kv", path=engine, options={"version": "2"}
            )
            print(f"[seed] Движок '{engine}' успешно включён.")
        except hvac.exceptions.InvalidRequest as e:
            if "path is already in use" in str(e):
                print(f"[seed] Движок '{engine}' уже существует.")
            else:
                print(f"[seed] Ошибка включения движка '{engine}': {e}")
                continue

        # Загружаем секреты
        count = 0
        for path, secret_data in secrets.items():
            client.secrets.kv.v2.create_or_update_secret(
                mount_point=engine, path=path, secret=secret_data
            )
            count += 1
        print(f"[seed] Движок '{engine}': загружено {count} секретов.")

    print("[seed] Тестовые данные успешно загружены в Vault.")


if __name__ == "__main__":
    print(f"[seed] Подключение к Vault: {VAULT_ADDR}")
    # Сначала пытаемся подключиться вообще без токена, чтобы проверить статус
    client = hvac.Client(url=VAULT_ADDR)
    
    wait_for_vault(client)
    init_and_unseal(client)
    
    # К этому моменту клиент аутентифицирован под root токеном
    seed(client)

