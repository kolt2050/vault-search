import os
import sys
import re
import logging
import argparse
import hvac
from typing import List
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import time
import tracemalloc

__version__ = "0.2.0"

# Настройка логирования
logger = logging.getLogger("vault_search")
logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

file_handler = logging.FileHandler('app.log', encoding='utf-8')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

class OIDCCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        self.server.callback_params = params
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Authentication successful!</h1><p>You can close this window and return to the terminal.</p></body></html>")
    
    def log_message(self, format, *args):
        pass

def get_cached_token() -> str:
    """Проверяет наличие валидного токена в ~/.vault-token."""
    token_file = os.path.expanduser('~/.vault-token')
    if not os.path.exists(token_file):
        return None
    try:
        with open(token_file, 'r') as f:
            token = f.read().strip()
        if not token:
            return None
        # Проверяем, что токен всё ещё валиден
        client = hvac.Client(url=os.getenv('VAULT_ADDR', 'http://127.0.0.1:8200'), token=token)
        client.auth.token.lookup_self()
        logger.info("Найден валидный кэшированный токен.")
        return token
    except Exception:
        return None

def perform_oidc_login(url: str, bootstrap_token: str = None) -> str:
    """Выполняет OIDC логин через Vault API и возвращает токен."""
    logger.info("Инициализация OIDC логина...")
    token_for_auth_url = bootstrap_token or os.getenv('VAULT_TOKEN', 'myroot')
    client = hvac.Client(url=url, token=token_for_auth_url)
    
    try:
        # hvac oidc_authorization_url_request по умолчанию использует path='oidc'
        # и строит URL auth/oidc/auth_url — это правильно, если auth method смонтирован на 'oidc'
        auth_url_req = client.auth.oidc.oidc_authorization_url_request(
            role='default',
            redirect_uri='http://localhost:8250/oidc/callback'
        )
        auth_url = auth_url_req['data'].get('auth_url')
    except Exception as e:
        logger.error(f"Ошибка при получении OIDC Authorization URL: {e}")
        sys.exit(1)

    if not auth_url:
        logger.error("Vault не вернул auth_url для OIDC.")
        sys.exit(1)

    # Запускаем локальный веб-сервер для получения callback
    server = HTTPServer(('localhost', 8250), OIDCCallbackHandler)
    server.callback_params = {}
    
    logger.info("Открываю браузер для входа...")
    webbrowser.open(auth_url)
    
    logger.info("Ожидание ответа от браузера (callback)...")
    server.handle_request()
    
    params = server.callback_params
    code = params.get('code', [''])[0]
    state = params.get('state', [''])[0]
    
    if not code or not state:
        logger.error("Не удалось получить code / state из OIDC callback.")
        sys.exit(1)
        
    try:
        auth_result = client.auth.oidc.oidc_callback(
            code=code,
            path='oidc',
            state=state,
            nonce=""
        )
        token = auth_result['auth']['client_token']
        logger.info("OIDC логин успешен!")
        # Сохраняем токен в ~/.vault-token для повторного использования
        token_file = os.path.expanduser('~/.vault-token')
        try:
            with open(token_file, 'w') as f:
                f.write(token)
            logger.info(f"Токен сохранён в {token_file}")
        except Exception as e:
            logger.debug(f"Не удалось сохранить токен: {e}")
        return token
    except Exception as e:
        logger.error(f"Ошибка при обработке OIDC callback в Vault: {e}")
        sys.exit(1)

class VaultSearcher:
    def __init__(self, url: str, token: str, delay: float = 0.01):
        self.client = hvac.Client(url=url, token=token)
        self.delay = delay
        self.api_calls = 0

    def connect(self):
        if not self.client.is_authenticated():
            logger.error("Не удалось аутентифицироваться в Vault")
            sys.exit(1)
        logger.info(f"Успешное подключение к Vault по адресу {self.client.url}")



    def search_keys(self, mount_point: str, current_path: str, search_term: str, results: List[str], mode: str = 'keys', find_empty: bool = False):
        """Рекурсивно ищет ключи в Vault (KV v2).
        
        mode: 'path' — только в путях секретов
              'keys' — только во внутренних ключах секретов
              'values' — только в значениях секретов
        find_empty: искать секреты без внутренних ключей (если True, ignore mode)
        """
        logger.debug(f"Обход директории: {mount_point}/{current_path}")
        search_path = (mode == 'path') and not find_empty
        search_keys = (mode == 'keys') or find_empty
        search_values = (mode == 'values') and not find_empty
        search_content = search_keys or search_values
        try:
            self.api_calls += 1
            list_response = self.client.secrets.kv.v2.list_secrets(
                mount_point=mount_point,
                path=current_path
            )
            if self.delay > 0:
                time.sleep(self.delay)
            keys = list_response.get('data', {}).get('keys', [])
            
            for key in keys:
                if key.endswith('/'):
                    # Это "папка", идем внутрь
                    new_path = f"{current_path}{key}" if current_path else key
                    self.search_keys(mount_point, new_path, search_term, results, mode, find_empty)
                else:
                    # Это "файл" спецификации секрета
                    full_path = f"{current_path}{key}" if current_path else key
                    absolute_path = f"{mount_point}/{full_path}"
                    
                    # Проверяем полный путь секрета (включая родительские директории)
                    if search_path and search_term.lower() in full_path.lower():
                        logger.info(f"Найден секрет по пути: {absolute_path}")
                        if absolute_path not in results:
                            results.append(absolute_path)

                    # Читаем содержимое секрета, чтобы проверить его внутренние ключи или значения
                    if search_content:
                        try:
                            self.api_calls += 1
                            read_response = self.client.secrets.kv.v2.read_secret_version(
                                mount_point=mount_point,
                                path=full_path,
                                raise_on_deleted_version=True
                            )
                            if self.delay > 0:
                                time.sleep(self.delay)
                            secret_data = read_response.get('data', {}).get('data', {})

                            if find_empty:
                                if not secret_data:
                                    # Проверяем, если задан search_term, то он должен входить в путь
                                    if not search_term or search_term.lower() in full_path.lower():
                                        logger.info(f"Найден пустой секрет: {absolute_path}")
                                        if absolute_path not in results:
                                            results.append(absolute_path)
                            else:
                                for internal_key, internal_value in secret_data.items():
                                    if search_keys and search_term.lower() in internal_key.lower():
                                        match_info = f"{absolute_path} -> ключ '{internal_key}'"
                                        logger.info(f"Найден ключ внутри секрета: {match_info}")
                                        if match_info not in results:
                                            results.append(match_info)
                                    if search_values and internal_value is not None and search_term.lower() in str(internal_value).lower():
                                        match_info = f"{absolute_path} -> ключ '{internal_key}' -> содержит искомое значение"
                                        logger.info(f"Найдено значение внутри секрета: {match_info}")
                                        if match_info not in results:
                                            results.append(match_info)
                        except Exception as e:
                            logger.debug(f"Ошибка при чтении секрета '{full_path}' (возможно, нет прав): {e}")
        except hvac.exceptions.InvalidPath:
            pass
        except Exception as e:
            logger.error(f"Ошибка при чтении пути '{mount_point}/{current_path}': {e}")

    def search_acl_policies(self, search_term: str, results: List[str]):
        """Ищет вхождение строки внутри path \"...\" блоков ACL Policies.
        
        Парсит HCL-правила каждой политики, извлекает пути из конструкций
        path \"some/path/*\" { ... } и проверяет вхождение search_term.
        """
        logger.info("Получаем список ACL Policies...")
        try:
            self.api_calls += 1
            response = self.client.sys.list_policies()
            if self.delay > 0:
                time.sleep(self.delay)
            policy_names = response.get('data', {}).get('policies', response.get('policies', []))
        except Exception as e:
            logger.error(f"Ошибка при получении списка политик: {e}", exc_info=True)
            return

        # Фильтруем системные политики (root, default)
        user_policies = [p for p in policy_names if p not in ('root',)]
        logger.info(f"Найдено {len(user_policies)} политик для анализа.")

        # Регулярное выражение для извлечения путей из HCL: path "..." 
        path_pattern = re.compile(r'path\s+"([^"]+)"')

        for policy_name in user_policies:
            try:
                self.api_calls += 1
                policy_data = self.client.sys.read_policy(name=policy_name)
                if self.delay > 0:
                    time.sleep(self.delay)
                # hvac может вернуть разную структуру в зависимости от версии
                if isinstance(policy_data, dict):
                    hcl_rules = policy_data.get('data', {}).get('rules', '') or policy_data.get('rules', '')
                else:
                    hcl_rules = str(policy_data)

                if not hcl_rules:
                    continue

                # Ищем все path "..." в HCL
                paths_found = path_pattern.findall(hcl_rules)

                for path_value in paths_found:
                    if search_term.lower() in path_value.lower():
                        match_info = f"policy: {policy_name} -> path \"{path_value}\""
                        logger.info(f"Найдено совпадение в ACL: {match_info}")
                        if match_info not in results:
                            results.append(match_info)
            except Exception as e:
                logger.debug(f"Ошибка при чтении политики '{policy_name}': {e}")



def main():
    start_wall = time.perf_counter()
    start_cpu = time.process_time()
    tracemalloc.start()

    logger.info(f"Запуск Vault Search v{__version__}")

    parser = argparse.ArgumentParser(description='Поиск по ключам, их содержимому и значениям во всех движках HashiCorp Vault')
    parser.add_argument('search_term', help='Часть пути, ключа или значения (любые вхождения), который нужно найти', nargs='?', default=os.getenv('SEARCH_TERM', ''))
    parser.add_argument('--url', default=os.getenv('VAULT_ADDR', 'http://127.0.0.1:8200'), help='URL сервера Vault')
    parser.add_argument('--token', default=os.getenv('VAULT_TOKEN', 'myroot'), help='Vault Token')
    parser.add_argument('--mount', required=True, help='Точка монтирования KV v2 (обязательный параметр). Пример: stage, preprod, prod')
    parser.add_argument('--mode', default='keys', choices=['path', 'keys', 'values'],
                        help='Режим поиска: "path" — только в путях секретов, "keys" — только во внутренних ключах, "values" — только в значениях (по умолчанию "keys")')
    parser.add_argument('--empty', action='store_true', help='Искать только пустые секреты (без ключей). Поисковый запрос применяется только к путям.')
    parser.add_argument('--acl', action='store_true', help='Искать строку внутри path "..." блоков ACL Policies (поиск по путям в правилах политик)')
    parser.add_argument('--auth', default='token', choices=['token', 'oidc'], help='Метод аутентификации: "token" (встроенный токен) или "oidc" (требует браузер для входа)')
    parser.add_argument('--delay', type=float, default=0.01, help='Задержка в секундах между API запросами к Vault (по умолчанию 0.01) для снижения нагрузки')

    args, unknown = parser.parse_known_args()

    # Если search_term начинается с '-', argparse считает его флагом.
    # В этом случае он попадает в unknown — подхватываем его,
    # если основной search_term содержит только дефолтное значение из env
    if unknown:
        if len(unknown) == 1 and (not args.search_term or args.search_term == os.getenv('SEARCH_TERM', '')):
            args.search_term = unknown[0]
        else:
            parser.error(f"Нераспознанные аргументы: {' '.join(unknown)}")

    # Исправляем аргументы, искажённые Git Bash (MINGW/MSYS2):
    # Git Bash превращает "/data/" в "C:/Program Files/Git/data/"
    # и "/+/" в "C:/Program Files/Git/+/"
    msys_prefix = re.match(r'^[A-Za-z]:/Program Files/Git/(.*)$', args.search_term)
    if msys_prefix:
        original = '/' + msys_prefix.group(1)
        logger.info(f"Обнаружена подмена MSYS/Git Bash: '{args.search_term}' -> '{original}'")
        args.search_term = original

    # Нормализуем двойные слэши (обходной приём для Git Bash: "//data/" -> "/data/")
    if args.search_term.startswith('//'):
        args.search_term = args.search_term[1:]

    if not args.search_term and not args.empty:
        logger.error("Не указан искомый ключ (поисковый запрос). Используйте аргумент командной строки или SEARCH_TERM.")
        sys.exit(1)

    if args.auth == 'oidc':
        # Проверяем кэшированный токен (аналог: if ! vault token lookup; then vault login --method=oidc)
        cached = get_cached_token()
        if cached:
            args.token = cached
        else:
            args.token = perform_oidc_login(url=args.url)

    searcher = VaultSearcher(url=args.url, token=args.token, delay=args.delay)
    searcher.connect()

    results = []

    if args.acl:
        # Режим поиска по ACL Policies
        logger.info(f"Начинаем поиск вхождений строки '{args.search_term}' в ACL Policies...")
        searcher.search_acl_policies(search_term=args.search_term, results=results)
        print(f"\n--- Результаты поиска по ACL Policies для '{args.search_term}' ---")
    else:
        # Обычный поиск по KV-секретам
        if args.empty:
            logger.info(f"Начинаем поиск ПУСТЫХ секретов (строка: '{args.search_term}')...")
        else:
            mode_names = {'path': 'только пути', 'keys': 'только ключи', 'values': 'только значения'}
            logger.info(f"Начинаем поиск вхождений строки '{args.search_term}' (режим: {mode_names[args.mode]})...")

        logger.info(f"=== Поиск в движке '{args.mount}' ===")
        searcher.search_keys(mount_point=args.mount, current_path="", search_term=args.search_term, results=results, mode=args.mode, find_empty=args.empty)

        print(f"\n--- Результаты поиска по запросу '{args.search_term}' ---")

    if not results:
        print("Ничего не найдено.")
        logger.info("Поиск завершен. Ничего не найдено.")
    else:
        for r in results:
            print(f"- {r}")
        logger.info(f"Поиск завершен. Найдено {len(results)} результатов.")

    # Вывод метрик потребления памяти и процессорного времени
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    wall_time = time.perf_counter() - start_wall
    cpu_time = time.process_time() - start_cpu
    
    api_calls = searcher.api_calls
    rps = api_calls / wall_time if wall_time > 0 else 0

    print(f"\n--- Мониторинг производительности ---")
    print(f"Всего запросов к API:      {api_calls}")
    print(f"Скорость (RPS):            {rps:.1f} req/s")
    print(f"Потребление памяти (пик):  {peak_mem / 1024 / 1024:.2f} MB")
    print(f"Процессорное время:        {cpu_time:.3f} сек")
    print(f"Реальное время (wall):     {wall_time:.3f} сек")
    
    logger.info(f"Performance: API Calls {api_calls} | RPS {rps:.1f} | Peak Memory {peak_mem / 1024 / 1024:.2f} MB | CPU {cpu_time:.3f}s | Wall {wall_time:.3f}s")

if __name__ == "__main__":
    main()
