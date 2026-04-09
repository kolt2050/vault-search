import os
import sys
import time
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault-dev:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "myroot")

# Ищем любой секрет (он гарантированно будет существовать благодаря seed)
TARGET_PATH = "v1/prod/data/admin-panel/keys"

# Настройки для достижения нужного RPS (~500)
# Количество параллельных потоков и задержка в каждом потоке
WORKERS = 10
DELAY = 0.02


def worker(worker_id):
    headers = {"X-Vault-Token": VAULT_TOKEN}
    url = f"{VAULT_ADDR}/{TARGET_PATH}"
    print(f"[load-tester-{worker_id}] Запущено для: {url}")
    
    while True:
        try:
            r = requests.get(url, headers=headers)
            # Мы не логируем каждый успешный запрос, чтобы не засорять stdout и не тратить в логах RPS
            if r.status_code != 200:
                print(f"[load-tester-{worker_id}] Неожиданный статус: {r.status_code}")
                # Если Vault задыхается и отвечает 429 или 5xx, чуть-чуть ждем
                time.sleep(1)
            time.sleep(DELAY)
        except Exception as e:
            print(f"[load-tester-{worker_id}] Ошибка: {e}")
            time.sleep(2)

def main():
    print(f"Запуск Vault Load Tester. Цель: постоянная нагрузка на {VAULT_ADDR}")
    print(f"Потоков: {WORKERS}, Пауза в потоке: {DELAY} сек")
    
    # Даем Vault время подняться перед запуском долбежки
    time.sleep(10)
    
    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as executor:
            for i in range(WORKERS):
                executor.submit(worker, i)
    except KeyboardInterrupt:
        print("\nОстановка...")
        sys.exit(0)

if __name__ == "__main__":
    main()
