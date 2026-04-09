import os
import sys
import time
import requests
from concurrent.futures import ThreadPoolExecutor

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault-dev:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "myroot")

# Ищем любой секрет
TARGET_PATH = "v1/prod/data/admin-panel/keys"

# Настройки для достижения нужного RPS
TARGET_RPS = int(os.getenv("TARGET_RPS", "500"))
WORKERS = int(os.getenv("WORKERS", "50"))

def worker_loop(worker_id):
    headers = {"X-Vault-Token": VAULT_TOKEN}
    url = f"{VAULT_ADDR}/{TARGET_PATH}"
    print(f"[constant-load-{worker_id}] Started for {url}")
    
    session = requests.Session()
    session.headers.update(headers)
    
    # Ожидаемое время между запросами для одного воркера, чтобы в сумме выдавать TARGET_RPS
    rps_per_worker = TARGET_RPS / WORKERS
    sleep_time = 1.0 / rps_per_worker if rps_per_worker > 0 else 0
    
    while True:
        start_time = time.time()
        try:
            r = session.get(url)
            if r.status_code != 200:
                print(f"[constant-load-{worker_id}] Unexpected HTTP status: {r.status_code}")
                time.sleep(1)
        except Exception as e:
            print(f"[constant-load-{worker_id}] HTTP Request error: {e}")
            time.sleep(2)
            
        elapsed = time.time() - start_time
        # Если запрос выполнился слишком быстро, дожидаемся нужного интервала
        if elapsed < sleep_time:
            time.sleep(sleep_time - elapsed)

def main():
    print(f"Starting Constant Load Tester. Target limit: ~{TARGET_RPS} RPS on {VAULT_ADDR}")
    print(f"Workers: {WORKERS}, Requests per worker/sec: {TARGET_RPS / WORKERS:.2f}")
    
    # Даем Vault время подняться перед запуском
    time.sleep(10)
    
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        for i in range(WORKERS):
            executor.submit(worker_loop, i)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopping...")
        sys.exit(0)
