import os
import sys
import re
import logging
import argparse
import hvac
from typing import List

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

class VaultSearcher:
    def __init__(self, url: str, token: str):
        self.client = hvac.Client(url=url, token=token)

    def connect(self):
        if not self.client.is_authenticated():
            logger.error("Не удалось аутентифицироваться в Vault")
            sys.exit(1)
        logger.info(f"Успешное подключение к Vault по адресу {self.client.url}")

    def get_kv2_mounts(self) -> List[str]:
        """Получает все точки монтирования (движки) типа KV v2."""
        logger.info("Сканируем Vault для поиска всех движков KV v2...")
        try:
            response = self.client.sys.list_mounted_secrets_engines()
            # hvac возвращает полный ответ API; движки находятся в 'data'
            mounts = response.get('data', response) if isinstance(response, dict) else {}
            kv_mounts = []
            for path, config in mounts.items():
                if isinstance(config, dict) and config.get('type') == 'kv' and config.get('options', {}).get('version') == '2':
                    kv_mounts.append(path.rstrip('/'))
            logger.info(f"Найдены движки: {', '.join(kv_mounts)}")
            return kv_mounts
        except Exception as e:
            logger.error(f"Ошибка при получении списка движков: {e}", exc_info=True)
            return []

    def search_keys(self, mount_point: str, current_path: str, search_term: str, results: List[str], mode: str = 'all', find_empty: bool = False):
        """Рекурсивно ищет ключи в Vault (KV v2).
        
        mode: 'all' — искать и в путях, и во внутренних ключах
              'path' — только в путях секретов
              'keys' — только во внутренних ключах секретов
        find_empty: искать секреты без внутренних ключей (если True, ignore mode)
        """
        logger.debug(f"Обход директории: {mount_point}/{current_path}")
        search_path = (mode in ('all', 'path')) and not find_empty
        search_keys = (mode in ('all', 'keys')) or find_empty
        try:
            list_response = self.client.secrets.kv.v2.list_secrets(
                mount_point=mount_point,
                path=current_path
            )
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

                    # Читаем содержимое секрета, чтобы проверить его внутренние ключи
                    if search_keys:
                        try:
                            read_response = self.client.secrets.kv.v2.read_secret_version(
                                mount_point=mount_point,
                                path=full_path,
                                raise_on_deleted_version=True
                            )
                            secret_data = read_response.get('data', {}).get('data', {})

                            if find_empty:
                                if not secret_data:
                                    # Проверяем, если задан search_term, то он должен входить в путь
                                    if not search_term or search_term.lower() in full_path.lower():
                                        logger.info(f"Найден пустой секрет: {absolute_path}")
                                        if absolute_path not in results:
                                            results.append(absolute_path)
                            else:
                                for internal_key in secret_data.keys():
                                    if search_term.lower() in internal_key.lower():
                                        match_info = f"{absolute_path} -> ключ '{internal_key}'"
                                        logger.info(f"Найден ключ внутри секрета: {match_info}")
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
            response = self.client.sys.list_policies()
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
                policy_data = self.client.sys.read_policy(name=policy_name)
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
    logger.info(f"Запуск Vault Search v{__version__}")

    parser = argparse.ArgumentParser(description='Поиск по ключам и их содержимому во всех движках HashiCorp Vault')
    parser.add_argument('search_term', help='Часть пути или внутреннего ключа (любые вхождения), который нужно найти', nargs='?', default=os.getenv('SEARCH_TERM', ''))
    parser.add_argument('--url', default=os.getenv('VAULT_ADDR', 'http://127.0.0.1:8200'), help='URL сервера Vault')
    parser.add_argument('--token', default=os.getenv('VAULT_TOKEN', 'myroot'), help='Vault Token')
    parser.add_argument('--mount', default='all', help='Точка монтирования (по умолчанию "all"). Если "all", ищет во всех доступных движках.')
    parser.add_argument('--mode', default='all', choices=['all', 'path', 'keys'],
                        help='Режим поиска: "all" — везде, "path" — только в путях секретов, "keys" — только во внутренних ключах (по умолчанию "all")')
    parser.add_argument('--empty', action='store_true', help='Искать только пустые секреты (без ключей). Поисковый запрос применяется только к путям.')
    parser.add_argument('--acl', action='store_true', help='Искать строку внутри path "..." блоков ACL Policies (поиск по путям в правилах политик)')

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

    searcher = VaultSearcher(url=args.url, token=args.token)
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
            mode_names = {'all': 'пути + ключи', 'path': 'только пути', 'keys': 'только ключи'}
            logger.info(f"Начинаем поиск вхождений строки '{args.search_term}' (режим: {mode_names[args.mode]})...")

        mounts_to_search = []
        if args.mount.lower() == 'all':
            mounts_to_search = searcher.get_kv2_mounts()
            if not mounts_to_search:
                logger.error("В Vault не найдено ни одного секретного хранилища формата KV v2.")
                sys.exit(1)
        else:
            mounts_to_search = [args.mount]

        for mount in mounts_to_search:
            logger.info(f"=== Поиск в движке '{mount}' ===")
            searcher.search_keys(mount_point=mount, current_path="", search_term=args.search_term, results=results, mode=args.mode, find_empty=args.empty)

        print(f"\n--- Результаты поиска по запросу '{args.search_term}' ---")

    if not results:
        print("Ничего не найдено.")
        logger.info("Поиск завершен. Ничего не найдено.")
    else:
        for r in results:
            print(f"- {r}")
        logger.info(f"Поиск завершен. Найдено {len(results)} результатов.")

if __name__ == "__main__":
    main()
