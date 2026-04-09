"""
Скрипт для наполнения Vault тестовыми ACL Policies.
Запускается отдельно от seed.py (KV-данных).
Ожидает готовности Vault, затем загружает политики из seed_acl_data.json.
"""
import os
import sys
import json
import time
import hvac

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault-dev:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "myroot")
SEED_FILE = os.path.join(os.path.dirname(__file__), "seed_acl_data.json")

INIT_FILE = "/vault/file/init.json"

MAX_RETRIES = 30
RETRY_INTERVAL = 2


def wait_for_vault(client: hvac.Client):
    """Ожидает, пока Vault станет доступен по HTTP."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            client.sys.is_initialized()
            print(f"[seed-acl] Vault доступен (HTTP отвечает, попытка {attempt})")
            return
        except Exception:
            pass
        print(f"[seed-acl] Vault ещё не отвечает по HTTP, ждём {RETRY_INTERVAL}с... (попытка {attempt}/{MAX_RETRIES})")
        time.sleep(RETRY_INTERVAL)

    print("[seed-acl] ОШИБКА: Vault не стал доступен за отведённое время.")
    sys.exit(1)


def authenticate(client: hvac.Client):
    """Аутентифицируется в Vault, используя init.json или VAULT_TOKEN."""
    # Пробуем использовать init.json (root-токен из инициализации)
    if os.path.exists(INIT_FILE):
        with open(INIT_FILE, "r", encoding="utf-8") as f:
            init_data = json.load(f)

        # Если Vault запечатан — распечатываем
        if client.sys.is_sealed():
            print("[seed-acl] Vault запечатан. Выполняю распечатывание (unseal)...")
            client.sys.submit_unseal_keys(keys=[init_data["keys"][0]])
            print("[seed-acl] Vault успешно распечатан.")

        client.token = init_data["root_token"]
    else:
        # Используем токен из переменной окружения
        client.token = VAULT_TOKEN

    if not client.is_authenticated():
        print("[seed-acl] ОШИБКА: Не удалось аутентифицироваться в Vault.")
        sys.exit(1)

    print("[seed-acl] Аутентификация успешна.")


def seed_acl_policies(client: hvac.Client):
    """Загружает ACL Policies из seed_acl_data.json."""
    if not os.path.exists(SEED_FILE):
        print(f"[seed-acl] Файл с тестовыми ACL Policies не найден: {SEED_FILE}")
        sys.exit(1)

    with open(SEED_FILE, "r", encoding="utf-8") as f:
        policies = json.load(f)

    count = 0
    for policy_name, policy_rules in policies.items():
        try:
            client.sys.create_or_update_policy(
                name=policy_name,
                policy=policy_rules,
            )
            count += 1
            print(f"[seed-acl] Политика '{policy_name}' создана/обновлена.")
        except Exception as e:
            print(f"[seed-acl] Ошибка при создании политики '{policy_name}': {e}")

    print(f"[seed-acl] Загружено {count} ACL Policies в Vault.")


if __name__ == "__main__":
    print(f"[seed-acl] Подключение к Vault: {VAULT_ADDR}")
    client = hvac.Client(url=VAULT_ADDR)

    wait_for_vault(client)
    authenticate(client)
    seed_acl_policies(client)

    print("[seed-acl] Тестовые ACL Policies успешно загружены.")
