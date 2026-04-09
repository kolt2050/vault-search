"""
Генератор тестовых данных для Vault.
Создаёт seed_data.json с 10 000 секретами, распределёнными
по движкам stage, preprod и prod с вложенностью до 6 уровней.
"""
import json
import random
import string
import os

random.seed(42)

ENVS = ["stage", "preprod", "prod"]
TARGET_TOTAL = 10000
KEYS_ADDED = 0

# Реалистичные названия сервисов / доменов / команд
SERVICES = [
    "auth-service", "api-gateway", "user-service", "payment-service",
    "notification-service", "billing-service", "order-service", "catalog-service",
    "search-service", "analytics-service", "logging-service", "monitoring-service",
    "cache-service", "queue-service", "scheduler-service", "report-service",
    "email-service", "sms-service", "file-storage", "cdn-service",
    "webhook-service", "audit-service", "config-service", "feature-flags",
    "session-service", "rate-limiter", "geo-service", "recommendation-engine",
    "ml-pipeline", "data-warehouse", "etl-service", "backup-service",
    "identity-provider", "oauth-proxy", "admin-panel", "cms-backend",
]

TEAMS = ["platform", "backend", "frontend", "infra", "data", "security", "mobile", "devops"]

REGIONS = ["eu-west-1", "us-east-1", "ap-southeast-1", "eu-central-1"]

CONFIG_TYPES = [
    "config", "credentials", "settings", "secrets", "connection",
    "tls", "certificates", "tokens", "keys", "endpoints",
]

# Типы внутренних ключей секретов
KEY_TEMPLATES = {
    "config": lambda env, svc: {
        "log_level": random.choice(["debug", "info", "warn", "error"]),
        "max_retries": str(random.randint(1, 10)),
        "timeout_ms": str(random.randint(100, 30000)),
        "feature_enabled": random.choice(["true", "false"]),
    },
    "credentials": lambda env, svc: {
        "username": f"{svc}_user_{env}",
        "password": rand_password(),
        "host": f"{svc}-db.{env}.internal:5432",
    },
    "settings": lambda env, svc: {
        "endpoint_url": f"https://{svc}.{env}.example.com/api/v1",
        "rate_limit": str(random.randint(10, 10000)),
        "cache_ttl_sec": str(random.randint(30, 3600)),
    },
    "secrets": lambda env, svc: {
        "api_key": f"sk_{env}_{''.join(random.choices(string.ascii_lowercase + string.digits, k=24))}",
        "api_secret": rand_password(),
    },
    "connection": lambda env, svc: {
        "dsn": f"postgres://{svc}:{rand_password()}@{svc}-db.{env}.internal:5432/{svc}",
        "pool_size": str(random.randint(5, 50)),
        "ssl_mode": random.choice(["require", "verify-full", "disable"]),
    },
    "tls": lambda env, svc: {
        "cert_pem": f"-----BEGIN CERTIFICATE-----\n{rand_b64(60)}\n-----END CERTIFICATE-----",
        "key_pem": f"-----BEGIN PRIVATE KEY-----\n{rand_b64(60)}\n-----END PRIVATE KEY-----",
    },
    "certificates": lambda env, svc: {
        "ca_bundle": f"-----BEGIN CERTIFICATE-----\n{rand_b64(80)}\n-----END CERTIFICATE-----",
        "expiry_date": f"2027-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
    },
    "tokens": lambda env, svc: {
        "access_token": f"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.{''.join(random.choices(string.ascii_letters, k=40))}",
        "refresh_token": rand_password(),
        "ttl": str(random.randint(300, 86400)),
    },
    "keys": lambda env, svc: {
        "encryption_key": rand_hex(32),
        "signing_key": rand_hex(32),
        "hmac_secret": rand_hex(16),
    },
    "endpoints": lambda env, svc: {
        "base_url": f"https://{svc}.{env}.example.com",
        "health_check": f"https://{svc}.{env}.example.com/healthz",
        "grpc_addr": f"{svc}-grpc.{env}.internal:9090",
    },
}

# Дополнительные подкомпоненты для глубокой вложенности
SUB_COMPONENTS = [
    "primary", "replica", "shard-0", "shard-1", "shard-2",
    "writer", "reader", "master", "slave",
    "internal", "external", "public", "private",
    "v1", "v2", "v3", "legacy", "canary", "stable",
    "cluster-a", "cluster-b",
]

INSTANCES = list(range(1, 51))  # instance numbering


def rand_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%"
    return "".join(random.choices(chars, k=length))


def rand_hex(length=16):
    return "".join(random.choices("0123456789abcdef", k=length))


def rand_b64(length=40):
    chars = string.ascii_letters + string.digits + "+/"
    return "".join(random.choices(chars, k=length))


def generate_path(depth: int, svc: str) -> str:
    """Генерирует путь с нужной глубиной вложенности."""
    parts = [svc]

    if depth >= 2:
        parts.append(random.choice(SUB_COMPONENTS))
    if depth >= 3:
        parts.append(random.choice(REGIONS))
    if depth >= 4:
        parts.append(f"instance-{random.choice(INSTANCES)}")
    if depth >= 5:
        parts.append(random.choice(TEAMS))
    if depth >= 6:
        parts.append(f"rev-{random.randint(1, 999)}")

    parts.append(random.choice(CONFIG_TYPES))
    return "/".join(parts)


def generate_secret(env: str, svc: str, config_type: str) -> dict:
    """Генерирует содержимое секрета."""
    template = KEY_TEMPLATES.get(config_type, KEY_TEMPLATES["config"])
    data = template(env, svc)
    # Иногда добавляем дополнительные ключи для разнообразия
    if random.random() < 0.3:
        data["notes"] = f"Auto-generated for {svc} in {env}"
    if random.random() < 0.15:
        data["owner_team"] = random.choice(TEAMS)
    if random.random() < 0.05:
        # Пустой секрет (для тестирования --empty)
        return {}
        
    # Добавляем по 5 различных ключей в каждый конечный секрет
    data["extra_key_a"] = rand_hex(8)
    data["extra_key_b"] = rand_hex(8)
    data["extra_key_c"] = rand_hex(8)
    data["extra_key_d"] = rand_hex(8)
    data["extra_key_e"] = rand_hex(8)
    
    global KEYS_ADDED
    KEYS_ADDED += 5
    
    return data


def main():
    result = {env: {} for env in ENVS}
    total = 0

    # Распределяем примерно поровну между окружениями
    per_env = TARGET_TOTAL // len(ENVS)

    for env in ENVS:
        count = 0
        used_paths = set()
        target = per_env if env != ENVS[-1] else TARGET_TOTAL - total

        while count < target:
            svc = random.choice(SERVICES)
            # Выбираем глубину вложенности (1-6) с перекосом к средним значениям
            depth = random.choices([1, 2, 3, 4, 5, 6], weights=[5, 15, 25, 25, 20, 10])[0]
            path = generate_path(depth, svc)

            # Избегаем дублей
            if path in used_paths:
                continue
            used_paths.add(path)

            config_type = path.rsplit("/", 1)[-1]
            secret = generate_secret(env, svc, config_type)
            result[env][path] = secret
            count += 1

        total += count
        print(f"[generate] {env}: {count} секретов")

    print(f"[generate] Итого: {total} секретов")
    print(f"[generate] Всего добавлено новых ключей: {KEYS_ADDED}")

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seed_data.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    file_size_mb = os.path.getsize(out_path) / (1024 * 1024)
    print(f"[generate] Файл записан: {out_path} ({file_size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
