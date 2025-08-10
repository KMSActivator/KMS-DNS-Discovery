# Поиск KMS-сервера через DNS SRV

`kms_dns_discovery.py` — это кроссплатформенный утилитный скрипт на Python для поиска корпоративных KMS-серверов через DNS SRV-записи `_vlmcs._tcp`.  
Скрипт помогает системным администраторам и инженерам быстро определить расположение KMS-сервера в домене, проверить сетевую доступность и при необходимости получить IP-адреса.

**Возможности:**
- Поиск SRV-записей `_vlmcs._tcp` в указанном или системном домене.
- Использование библиотеки **dnspython** (при наличии) или системных утилит `nslookup` / `dig` в качестве fallback.
- Опциональное разрешение A/AAAA записей для найденных хостов.
- Опциональная проверка доступности TCP-порта (по умолчанию 1688).
- Вывод результатов в форматах: **table** (по умолчанию), **json**, **csv**.
- Корректные коды возврата для автоматизации и интеграции.

## Требования

- Python **3.8+**
- Для расширенного DNS-функционала рекомендуется установить [dnspython](https://pypi.org/project/dnspython/):

```bash
pip install dnspython
```

* При отсутствии dnspython используются системные утилиты:

  * **Windows:** `nslookup`
  * **Linux/macOS:** `nslookup` или `dig`

## Установка

1. Склонируйте репозиторий:

   ```bash
   git clone https://github.com/KMSActivator/KMS-DNS-Discovery.git
   cd KMS-DNS-Discovery
   ```

2. Сделайте скрипт исполняемым (Linux/macOS):

   ```bash
   chmod +x kms_dns_discovery.py
   ```

3. (Необязательно) Установите dnspython:

   ```bash
   pip install dnspython
   ```

## Использование

### Примеры запуска

* **Базовый поиск** (используется системный домен поиска):

  ```bash
  python kms_dns_discovery.py
  ```

* **Указание домена и вывод в JSON**:

  ```bash
  python kms_dns_discovery.py -d corp.example.com -f json
  ```

* **Проверка TCP-порта и резолвинг адресов**:

  ```bash
  python kms_dns_discovery.py -V --resolve-a
  ```

* **Запрос через конкретный DNS-сервер**:

  ```bash
  python kms_dns_discovery.py -n 10.0.0.53 -t 5 --tries 3
  ```

### Справка по параметрам

```
-d, --domain <STRING>         Указать DNS-домен (например, corp.example.com)
-n, --nameserver <IP>         Указать адрес DNS-сервера (можно несколько раз)
-t, --timeout <FLOAT>         Таймаут DNS/TCP-запроса (секунды)
--tries <INT>                 Количество попыток DNS-запроса
--resolve-a                   Разрешить A/AAAA для целевых хостов
-V, --verify-port              Проверить доступность TCP-порта (по умолчанию 1688)
--port <INT>                  Порт для проверки (по умолчанию 1688)
-f, --format <table|json|csv> Формат вывода (по умолчанию table)
-q, --quiet                   Минимизировать вывод
--raw                         Показать «сырой» ответ DNS (отладка)
--version                     Показать версию и выйти
```

## Коды возврата

* **0** — записи найдены (и/или есть доступный порт при `--verify-port`)
* **2** — SRV-записи не найдены (NXDOMAIN/NoData)
* **3** — SRV найдены, но все проверки TCP неудачны (при `--verify-port`)
* **1** — ошибка выполнения (сеть, аргументы, внутренние сбои)

## Примеры вывода

**table**:

```
HOST                         PORT  PRIO  WEIGHT  TTL   ADDRESSES              REACHABLE
kms1.corp.example.com        1688     0     100  3600  10.0.0.10              yes
kms2.corp.example.com        1688    10      50  3600  10.0.0.11; 2001:db8::2 no
```

**json**:

```json
{
  "query": "_vlmcs._tcp.corp.example.com",
  "timestamp": "2025-08-10T12:34:56Z",
  "results": [
    {
      "host": "kms1.corp.example.com",
      "port": 1688,
      "priority": 0,
      "weight": 100,
      "ttl": 3600,
      "addresses": ["10.0.0.10"],
      "reachable": true
    }
  ]
}
```
