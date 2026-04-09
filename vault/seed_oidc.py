"""
Скрипт настройки OIDC Auth Method в Vault.
Vault выступает как OIDC-клиент, а Keycloak — как внешний Identity Provider.

Ожидает готовности Vault и Keycloak, затем настраивает:
- OIDC Auth Method
- Конфигурацию OIDC (discovery URL, client_id, client_secret)
- Роль 'default' с привязкой к политике 'readonly'
"""
import os
import sys
import json
import time
import urllib.request
import urllib.error
import hvac

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault-dev:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "myroot")
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
# URL, доступный и для Vault-контейнера, и для браузера пользователя
KEYCLOAK_EXTERNAL_URL = os.getenv("KEYCLOAK_EXTERNAL_URL", "http://localhost:9080")

INIT_FILE = "/vault/file/init.json"

# Keycloak OIDC settings
KEYCLOAK_REALM = "vault"
OIDC_CLIENT_ID = "vault-search"
OIDC_CLIENT_SECRET = "vault-search-secret"

MAX_RETRIES = 30
RETRY_INTERVAL = 2


def wait_for_vault(client: hvac.Client):
    """Ожидает, пока Vault станет доступен и аутентифицируется."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            if client.sys.is_initialized():
                print(f"[seed-oidc] Vault доступен (попытка {attempt})")
                return
        except Exception:
            pass
        print(f"[seed-oidc] Vault ещё не отвечает, ждём {RETRY_INTERVAL}с... ({attempt}/{MAX_RETRIES})")
        time.sleep(RETRY_INTERVAL)

    print("[seed-oidc] ОШИБКА: Vault не стал доступен за отведённое время.")
    sys.exit(1)


def authenticate(client: hvac.Client):
    """Аутентифицируется в Vault, используя init.json или VAULT_TOKEN."""
    if os.path.exists(INIT_FILE):
        with open(INIT_FILE, "r", encoding="utf-8") as f:
            init_data = json.load(f)

        if client.sys.is_sealed():
            print("[seed-oidc] Vault запечатан. Выполняю распечатывание (unseal)...")
            client.sys.submit_unseal_keys(keys=[init_data["keys"][0]])
            print("[seed-oidc] Vault успешно распечатан.")

        client.token = init_data["root_token"]
    else:
        client.token = VAULT_TOKEN

    if not client.is_authenticated():
        print("[seed-oidc] ОШИБКА: Не удалось аутентифицироваться в Vault.")
        sys.exit(1)

    print("[seed-oidc] Аутентификация в Vault успешна.")


def wait_for_keycloak():
    """Ожидает, пока Keycloak станет доступен (проверяет OIDC discovery endpoint)."""
    discovery_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration"
    print(f"[seed-oidc] Ожидаем Keycloak: {discovery_url}")

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(discovery_url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    print(f"[seed-oidc] Keycloak доступен (попытка {attempt})")
                    return
        except (urllib.error.URLError, urllib.error.HTTPError, Exception):
            pass
        print(f"[seed-oidc] Keycloak ещё не отвечает, ждём {RETRY_INTERVAL}с... ({attempt}/{MAX_RETRIES})")
        time.sleep(RETRY_INTERVAL)

    print("[seed-oidc] ОШИБКА: Keycloak не стал доступен за отведённое время.")
    sys.exit(1)


def configure_oidc(client: hvac.Client):
    """Настраивает OIDC Auth Method в Vault для работы с Keycloak."""

    # 1. Создаём политику readonly
    readonly_policy = 'path "*" { capabilities = ["read", "list"] }'
    client.sys.create_or_update_policy(name='readonly', policy=readonly_policy)
    print("[seed-oidc] Политика 'readonly' создана/обновлена.")

    # 2. Включаем OIDC Auth Method
    try:
        client.sys.enable_auth_method(method_type='oidc', path='oidc')
        print("[seed-oidc] OIDC auth method включен.")
    except hvac.exceptions.InvalidRequest as e:
        if "path is already in use" in str(e):
            print("[seed-oidc] OIDC auth method уже включен.")
        else:
            raise

    # 3. Конфигурируем OIDC
    # Discovery URL должен быть доступен и для Vault-контейнера (server-to-server),
    # и для браузера пользователя (authorization redirect).
    # Используем host.docker.internal:9080 — Vault резолвит через extra_hosts,
    # а браузер будет перенаправлен на localhost:9080 (Keycloak возвращает URL из запроса).
    oidc_discovery_url = f"{KEYCLOAK_EXTERNAL_URL}/realms/{KEYCLOAK_REALM}"

    client.write('auth/oidc/config',
                 oidc_discovery_url=oidc_discovery_url,
                 oidc_client_id=OIDC_CLIENT_ID,
                 oidc_client_secret=OIDC_CLIENT_SECRET,
                 default_role="default")
    print(f"[seed-oidc] OIDC конфигурация обновлена. Discovery URL: {oidc_discovery_url}")

    # 4. Создаём роль default
    client.write('auth/oidc/role/default',
                 allowed_redirect_uris=[
                     "http://localhost:8250/oidc/callback",
                     "http://localhost:8200/ui/vault/auth/oidc/oidc/callback",
                 ],
                 user_claim="preferred_username",
                 token_policies=["readonly"],
                 oidc_scopes=["openid", "profile", "email"])
    print("[seed-oidc] Роль OIDC 'default' создана.")

    print("[seed-oidc] Vault OIDC настроен. Keycloak — внешний Identity Provider.")


if __name__ == "__main__":
    print(f"[seed-oidc] Подключение к Vault: {VAULT_ADDR}")
    print(f"[seed-oidc] Keycloak URL: {KEYCLOAK_URL}")

    client = hvac.Client(url=VAULT_ADDR)

    wait_for_vault(client)
    authenticate(client)
    wait_for_keycloak()
    configure_oidc(client)

    print("[seed-oidc] Готово! OIDC полностью настроен.")
