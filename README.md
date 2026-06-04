# tunnel-testing

Фреймворк для тестирования обнаружения прокси-туннелей.

Запускает набор из восьми детекционных метрик (M1–M8) против живого или
заранее захваченного трафика туннеля и выдаёт структурированный JSON-отчёт
с итоговым вердиктом **PASS** / **FAIL**.

---

## Содержание

1. [Концепция](#концепция)
2. [Архитектура](#архитектура)
3. [Предварительные требования](#предварительные-требования)
4. [Установка](#установка)
5. [Быстрый старт](#быстрый-старт)
6. [Режимы запуска](#режимы-запуска)
7. [Описание метрик M1–M8](#описание-метрик-m1m8)
8. [Трафик-сценарии](#трафик-сценарии)
9. [Выходные артефакты](#выходные-артефакты)
10. [Формат отчёта](#формат-отчёта)
11. [Логика вердикта](#логика-вердикта)
12. [Настройка порогов](#настройка-порогов)
13. [ML-модель для M4](#ml-модель-для-m4)
14. [Кастомные правила Suricata](#кастомные-правила-suricata)
15. [Docker-образ nDPI](#docker-образ-ndpi)
16. [Сравнение конфигураций (compare.py)](#сравнение-конфигураций-comparepy)
17. [Расширение фреймворка](#расширение-фреймворка)
18. [Структура проекта](#структура-проекта)
19. [Справка по CLI](#справка-по-cli)

---

## Концепция

**tunnel-gen** генерирует конфигурации прокси-туннелей, которые должны выглядеть
как обычный HTTPS-трафик — чтобы их не заблокировали DPI-системы или IDS.
Данный фреймворк отвечает на вопрос: *«Насколько хорошо конкретная конфигурация
туннеля сопротивляется обнаружению?»*

Тест проходит следующие стадии:

```
DSL-конфиг (.yaml)
       │
       ▼
┌──────────────┐   сборка Go   ┌───────────────────────┐
│  tunnel-gen  │ ─────────────►│ tunnel-server + client │
│  (go build)  │               │ слушают на localhost   │
└──────────────┘               └──────────┬────────────┘
                                          │ SOCKS5 прокси
                               ┌──────────▼────────────┐
                               │   трафик-сценарий      │
                               │ web / bulk / idle      │
                               └──────────┬────────────┘
                                          │
                               ┌──────────▼────────────┐
                               │    tcpdump capture     │
                               │    → capture.pcap      │
                               └──────────┬────────────┘
                                          │
              ┌───────────────────────────┼─────────────────────┐
              ▼           ▼              ▼          ▼           ▼
          M1 nDPI    M2 Suricata    M3 Zeek    M4-M7 flow_ml  M8 probe
         (Docker)     (Docker)     (Docker)   (Python/sklearn) (TCP)
              │           │              │          │           │
              └───────────┴──────────────┴──────────┴───────────┘
                                          │
                               ┌──────────▼────────────┐
                               │      report.json       │
                               │   PASS / FAIL + детали │
                               └───────────────────────┘
```

---

## Архитектура

```
run_test.py          ← CLI-точка входа (argparse)
tester/
  config.py          ← TestConfig — все параметры одного запуска
  runner.py          ← TestRunner — оркестратор (запускает стадии 1–6)
  tunnel.py          ← запуск/остановка tunnel-server + tunnel-client
  capture.py         ← обёртка над tcpdump
  traffic.py         ← генераторы трафика (web / bulk / idle)
  report.py          ← сборка отчёта + вердикт
  analyzers/
    ndpi.py          ← M1: DPI-классификация через nDPI
    suricata.py      ← M2: IDS-анализ через Suricata
    zeek.py          ← M3: JA3/JA4 и TLS-метаданные через Zeek
    flow_ml.py       ← M4/M5/M6/M7: ML-эвристики + дивергенция KL
    probe.py         ← M8: активное зондирование
  utils/
    docker_run.py    ← обёртка над `docker run --rm`
    pcap_parse.py    ← разбор PCAP + извлечение признаков потоков
rules/
  custom.rules       ← кастомные правила Suricata
docker/
  ndpi/Dockerfile    ← сборка образа tunnel-testing/ndpi:latest
```

Каждый модуль-анализатор имеет единственную публичную функцию:

```python
def analyze(pcap_path: Path, output_dir: Path, **kwargs) -> dict: ...
```

Возвращаемый словарь содержит сырые метрики. `runner.py` передаёт их в
`report.py`, который применяет пороговые условия и формирует итоговый JSON.

---

## Предварительные требования

| Компонент | Версия | Примечание |
|---|---|---|
| Python | ≥ 3.10 | |
| Go | ≥ 1.21 | для сборки tunnel-gen |
| Docker | любая актуальная | M1, M2, M3 |
| tcpdump | любая | должен быть в `PATH` |
| root / sudo | — | tcpdump требует привилегий для захвата |

Аналитические Docker-образы, которые будут скачаны автоматически:

| Образ | Используется в |
|---|---|
| `tunnel-testing/ndpi:latest` | M1 — нужно собрать вручную (см. ниже) |
| `jasonish/suricata:latest` | M2 |
| `zeek/zeek:latest` | M3 |

---

## Установка

```bash
# 1. Клонировать репозиторий (tunnel-testing лежит рядом с tunnel-gen)
git clone <repo>
cd tunnel-testing

# 2. Установить Python-зависимости
pip install -r requirements.txt

# 3. Собрать Docker-образ nDPI (один раз)
docker build -t tunnel-testing/ndpi:latest docker/ndpi/

# 4. Убедиться, что tunnel-gen собирается
cd ../tunnel-gen
go build ./...
cd ../tunnel-testing
```

### requirements.txt

```
pyyaml>=6.0          # чтение DSL-конфигов
requests>=2.31       # HTTP-трафик в сценарии web
PySocks>=1.7.1       # SOCKS5 для requests
scapy>=2.5           # первичный парсер PCAP
scikit-learn>=1.4    # опциональная sklearn-модель для M4
numpy>=1.26          # зависимость sklearn
scipy>=1.12          # зависимость
tqdm>=4.66           # прогресс-бар (опционально)
```

---

## Быстрый старт

```bash
# Полный запуск: собрать туннель, захватить трафик, проанализировать
python run_test.py \
  --config  ..\tunnel-gen\examples\tls-token.yaml \
  --root    ../tunnel-gen \
  --scenario web \
  --duration 30 \
  --output  ./results/run-01
```

После завершения:

```
============================================================
  VERDICT: PASS
============================================================
  Check                   Result  Detail
------------------------------------------------------------
  ✓ M1_ndpi               PASS    classified_as=TLS  is_known_vpn=False
  ✓ M2_suricata           PASS    alert_count=0
  ✓ M3_ja3                PASS    ja3_is_browser=True  browser_matches=[Firefox-120]  high_entropy_streams=0
  ✓ M4_vpn_prob           PASS    vpn_prob=0.312
  ✓ M5_vpn_prob_seq       PASS    vpn_prob_seq=0.280
  ✓ M6_kl_len             PASS    kl_len=0.118
  ✓ M7_kl_iat             PASS    kl_iat=0.093
  ✓ M8_probe              PASS    distinguishable_ratio=0.000  flags=0
============================================================
```

---

## Режимы запуска

### 1. Полный автоматический режим

Фреймворк сам собирает бинари, запускает сервер и клиент, захватывает трафик,
анализирует PCAP и сохраняет отчёт.

```bash
python run_test.py \
  --config  ../tunnel-gen/configs/example.yaml \
  --root    ../tunnel-gen \
  --scenario web \
  --duration 60 \
  --iface   eth0 \
  --output  ./results/run-01
```

### 2. Анализ готового PCAP

Туннель не запускается и не захватывается — анализируется существующий файл.
Полезно для сравнения конфигов на одном и том же трафике.

```bash
python run_test.py \
  --config ../tunnel-gen/configs/example.yaml \
  --root   ../tunnel-gen \
  --pcap   ./captures/baseline.pcap \
  --output ./results/analysis-01
```

При передаче `--pcap` флаг `--no-tunnel` устанавливается автоматически.

### 3. Туннель уже запущен (внешний)

Если туннель запущен отдельно (например, в другой консоли):

```bash
python run_test.py \
  --config   ../tunnel-gen/configs/example.yaml \
  --root     ../tunnel-gen \
  --no-tunnel \
  --socks5   127.0.0.1:1080 \
  --scenario bulk \
  --duration 30 \
  --output   ./results/run-02
```

### 4. Выборочный запуск анализаторов

```bash
# Пропустить тяжёлые Docker-анализаторы при отладке
python run_test.py \
  --config ../tunnel-gen/configs/example.yaml \
  --root   ../tunnel-gen \
  --pcap   ./capture.pcap \
  --skip   suricata zeek \
  --output ./results/run-03

# Запустить только M8 (активное зондирование)
python run_test.py \
  --config ../tunnel-gen/configs/example.yaml \
  --root   ../tunnel-gen \
  --pcap   ./capture.pcap \
  --only   probe \
  --output ./results/run-04
```

---

## Описание метрик M1–M8

### M1 — nDPI: классификация по DPI

**Модуль:** `tester/analyzers/ndpi.py`  
**Инструмент:** `ndpiReader` (Docker-образ `tunnel-testing/ndpi:latest`)  
**Вес в вердикте:** критический

nDPI — библиотека глубокой инспекции пакетов от ntop. `ndpiReader` принимает
PCAP-файл и классифицирует каждый поток по протоколу.

**Особенности реализации:**
- Образ `tunnel-testing/ndpi:latest` устанавливает пакет `libndpi-bin` из официального
  репозитория ntop (`apt-ntop-stable`) для Ubuntu 22.04.
- ndpiReader 4.x не поддерживает Windows-loopback захваты (DLT_NULL, link type 0) —
  он молча пропускает все пакеты. Скрипт `pcap_normalize.py` конвертирует DLT_NULL →
  DLT_RAW перед запуском, снимая 4-байтовый AF-заголовок с каждого пакета.
- Флаг `-J` (JSON) в ndpiReader 4.2 сломан; вместо него используется `-C` (per-flow CSV).

Что делает анализатор:
1. Запускает `ndpiReader -i /capture.pcap -q -C /output/ndpi_flows.csv -w /output/ndpi_summary.txt`
   в Docker через обёртку `ndpi_entrypoint.sh`, которая вызывает `pcap_normalize.py`
   автоматически при обнаружении DLT_NULL.
2. Разбирает per-flow CSV: поля `ndpi_proto`, `ja3c`, `ja3s`, `server_name_sni`, `tls_version`.
3. Определяет топовый протокол по количеству потоков.
4. Проверяет, входит ли он в список явных VPN-протоколов.

```python
KNOWN_VPN = {
    "OpenVPN", "WireGuard", "Shadowsocks", "VMess",
    "Tor", "I2P", "GRE", "L2TP", "PPTP", "IPIP",
}
ACCEPTABLE = {"TLS", "HTTPS", "TLSv1", "TLSv1.2", "TLSv1.3", "QUIC", "Unknown", "UNKNOWN"}
```

**Метрики на выходе:**

| Поле | Тип | Описание |
|---|---|---|
| `classified_as` | str | Топ-протокол по количеству потоков |
| `is_known_vpn` | bool | Попадает ли топ-протокол в `KNOWN_VPN` |
| `is_acceptable` | bool | Попадает ли топ-протокол в `ACCEPTABLE` |
| `flow_count` | int | Общее число потоков в CSV |
| `known_flow_count` | int | Потоки с DPI-уверенностью (из `ndpi_summary.txt`) |
| `protocol_distribution` | dict | `{"TLS": 42, "DNS": 5, ...}` |
| `ja3_hashes` | list | JA3-хэши клиентов (поле `ja3c`) |
| `ja4_hashes` | list | JA3S-хэши серверов (поле `ja3s`) |
| `sni_set` | list | SNI-имена из `server_name_sni` |
| `tls_versions` | list | Версии TLS из `tls_version` |

**Критерий PASS:** `is_known_vpn == False`

---

### M2 — Suricata: IDS-алерты

**Модуль:** `tester/analyzers/suricata.py`  
**Инструмент:** `jasonish/suricata:latest` (Docker)  
**Вес в вердикте:** критический

Suricata — IDS/IPS с поддержкой правил в формате Snort/Suricata. Анализатор
запускает Suricata в офлайн-режиме (`-r /capture.pcap`) с правилами
[Emerging Threats Open](https://rules.emergingthreats.net/) + кастомными
правилами из `rules/custom.rules`.

**Правила ET Open** скачиваются автоматически при первом запуске (~50 МБ)
и кешируются в `rules/emerging-all.rules`. Источник:
`https://rules.emergingthreats.net/open/suricata-7.0.3/rules/emerging-all.rules`

**Кастомные правила** (`rules/custom.rules`) проверяют туннельно-специфичные
паттерны, которые не покрывает ET Open:
- Однородные большие UDP-пакеты (WireGuard-подобный трафик)
- TLS ClientHello без SNI
- Длительные TLS-сессии на нестандартных портах
- HTTP CONNECT туннелирование
- Паттерн рукопожатия Noise Protocol

Что делает анализатор:
1. Монтирует PCAP и директорию с правилами в контейнер.
2. Запускает `suricata -r /capture.pcap -l /output -S /rules/emerging-all.rules`.
3. Разбирает `eve.json` (EVE-лог в JSON-lines формате).
4. Извлекает события типов `alert`, `flow`, `tls`.

**Метрики на выходе:**

| Поле | Тип | Описание |
|---|---|---|
| `alert_count` | int | Общее число алертов |
| `alerts` | list | Первые 20 алертов с полями `signature`, `category`, `severity`, `src`, `dst`, `dport` |
| `flow_count` | int | Число записанных потоков |
| `tls_count` | int | Число TLS-событий |
| `tls_versions` | list | Обнаруженные версии TLS |
| `tls_sni` | list | SNI-имена из TLS-рукопожатий |
| `categories` | list | Уникальные категории сработавших правил |

**Критерий PASS:** `alert_count == 0`

---

### M3 — Zeek / JA3: TLS-фингерпринт

**Модуль:** `tester/analyzers/zeek.py`  
**Инструмент:** `zeek/zeek:latest` (Docker)  
**Вес в вердикте:** средний

Zeek (бывший Bro) — платформа для анализа сетевого трафика. Анализатор
загружает скрипты `base/protocols/ssl` и `policy/protocols/ssl/ssl-log-ext`,
которые генерируют `ssl.log` с полями `ja3`, `ja3s`, `server_name`, `cipher`,
`version`.

**JA3** — MD5-хэш от параметров TLS ClientHello (версия, шифры,
расширения, эллиптические кривые). Разные реализации TLS имеют уникальные
хэши, что позволяет определить, соответствует ли фингерпринт реальному
браузеру.

```python
BROWSER_JA3 = {
    "Chrome-120":  "8f52d1ce3e845a97d2804a2e4e0f5699",
    "Firefox-120": "25b4dbb5ff6d68c1e91e3d1f741f5bec",
    "Safari-17":   "773906b0efdefa24a7f2b8eb6985bf37",
    "Edge-120":    "b32309a26951912be7dba376398abc3b",
}
```

> **Замечание:** JA3-хэши браузеров меняются с каждым обновлением. Список
> в `zeek.py` нужно актуализировать под целевые браузерные версии.

**Энтропийный анализ сырого зашифрованного трафика:**

Помимо JA3, анализатор вычисляет побайтовую энтропию Шеннона TCP-нагрузки
на стороне Python (без Docker). Это позволяет обнаружить сырые
зашифрованные туннели (Noise Protocol, нестандартные AEAD-протоколы),
которые не экспонируют TLS-рукопожатие.

```
Encrypted/ChaCha20  ≈ 7.8–8.0 бит   → high_entropy_stream
Compressed HTTP     ≈ 7.1–7.2 бит   → НЕ флагируется (SOCKS5/gzip)
Plain HTTP          ≈ 4.0–5.0 бит
```

Порог: `entropy > 6.5` бит + минимум 500 байт в потоке → поток считается
высокоэнтропийным. Потоки с известными сигнатурами (`TLS 0x16 0x03`,
`HTTP GET`, `SSH-`, `SOCKS5 0x05 0x00`) исключаются.

Что делает анализатор:
1. Вычисляет энтропию TCP-нагрузки из PCAP (Python, до Docker).
2. Записывает встроенный Zeek-скрипт в `output_dir/zeek_scripts/local.zeek`.
3. Запускает `zeek -r /capture.pcap /scripts/local.zeek` в Docker
   с раздельным монтированием: `/logs` ← `output_dir/zeek/`, `/scripts` ← `output_dir/zeek_scripts/`.
4. Разбирает TSV-форматированные `ssl.log` и `conn.log`.

**Метрики на выходе:**

| Поле | Тип | Описание |
|---|---|---|
| `ja3_hashes` | list | Все уникальные JA3-хэши клиентов |
| `ja3s_hashes` | list | Все уникальные JA3S-хэши серверов |
| `snis` | list | SNI-имена из ClientHello |
| `cipher_suites` | list | Согласованные наборы шифров |
| `tls_versions` | list | Версии TLS |
| `browser_matches` | list | Браузеры с совпадающим JA3 |
| `ja3_is_browser` | bool | Хотя бы один JA3 совпал с браузером |
| `unique_ja3_count` | int | Число уникальных JA3-хэшей |
| `conn_count` | int | Число TCP-соединений |
| `unknown_service_conns` | int | Соединения без распознанного сервиса (Zeek conn.log) |
| `high_entropy_streams` | int | Потоков с энтропией > 6.5 бит (сырой зашифрованный трафик) |
| `payload_byte_entropy` | float | Средняя побайтовая энтропия всех TCP-потоков |

**Критерий PASS:**
- `ja3_is_browser == True` — JA3 совпал с реальным браузером, **ИЛИ**
- `unique_ja3_count == 0` **И** `high_entropy_streams == 0` — нет ни TLS-фингерпринта,
  ни высокоэнтропийных потоков (например, туннель скрыт за легитимным прокси).

Если `unique_ja3_count == 0`, но `high_entropy_streams > 0` (как в случае
`detectable-raw-noise.yaml`), проверка **не проходит** — сырой Noise Protocol обнаружен.

---

### M4 — ML flow classifier: вероятность VPN на уровне потоков

**Модуль:** `tester/analyzers/flow_ml.py`  
**Инструмент:** Python (эвристика) или sklearn-модель  
**Вес в вердикте:** средний

Классификатор работает на уровне агрегированных статистических признаков
двунаправленных потоков (~35 признаков в стиле CICFlowMeter).

**Эвристический классификатор** (используется по умолчанию) основан на
наблюдении, что VPN-туннели с шифрованием имеют характерные свойства:

| Признак | Логика | Вес |
|---|---|---|
| Среднее значение длины пакета | Чем ближе к MTU (1300 байт), тем VPN-подобнее | 0.30 |
| Коэффициент вариации длин | Низкий CV → равномерные фреймы (AEAD padding) | 0.20 |
| Доля маленьких пакетов (< 100 байт) | Мало ACK → VPN-like | 0.20 |
| Симметрия байт вперёд/назад | Симметричный обмен → VPN-like | 0.15 |
| CV межпакетных интервалов | Регулярные IAT → traffic shaping | 0.15 |

**Метрики на выходе:**

| Поле | Описание |
|---|---|
| `vpn_prob` | Вероятность VPN [0.0, 1.0] по признакам потоков |
| `total_packets` | Общее число пакетов в PCAP |
| `total_flows` | Число двунаправленных потоков |
| `total_bytes` | Суммарный объём (IP-датаграммы) |
| `duration_s` | Длительность захвата в секундах |
| `pkt_len_mean` | Среднее значение длины пакета |
| `pkt_len_std` | Стандартное отклонение длин |
| `iat_mean_ms` | Среднее межпакетное время (мс) |
| `small_pkt_pct` | % пакетов < 100 байт |
| `large_pkt_pct` | % пакетов > 1200 байт |
| `model_used` | `"heuristic"` или `"sklearn"` |

**Критерий PASS:** `vpn_prob < 0.65`

---

### M5 — Packet-sequence classifier: вероятность VPN по первым пакетам

**Модуль:** `tester/analyzers/flow_ml.py`  
**Вес в вердикте:** средний

Дополнительный классификатор, работающий только по **первым 20 пакетам**
(без ожидания завершения сессии). Имитирует поведение потокового DPI,
который должен классифицировать трафик в реальном времени.

Логика:

| Признак | Вес |
|---|---|
| Среднее значение длин первых 5 пакетов (рукопожатие) | 0.30 |
| Доля пакетов > 500 байт среди первых 20 | 0.40 |
| CV длин первых 20 пакетов | 0.30 |

**Критерий PASS:** `vpn_prob_seq < 0.65`

---

### M6 — KL-дивергенция длин пакетов

**Модуль:** `tester/analyzers/flow_ml.py`  
**Вес в вердикте:** средний

Вычисляет информационное расстояние между наблюдаемым распределением длин
пакетов и эталонным распределением для HTTPS-трафика:

```
D_KL(P_observed ‖ P_reference_HTTPS)
```

**Эталонное распределение** (из опубликованных исследований HTTPS-трафика):

| Диапазон | Вероятность | Интерпретация |
|---|---|---|
| 0–100 байт | 0.32 | ACK, TLS-записи без данных |
| 100–300 байт | 0.08 | Небольшие TLS-рукопожатия |
| 300–600 байт | 0.07 | |
| 600–900 байт | 0.07 | |
| 900–1200 байт | 0.10 | |
| 1200–1600 байт | 0.24 | Данные TLS-записей (MTU) |
| > 1600 байт | 0.12 | Jumbo / GSO |

Значение 0.0 означает идеальное совпадение с HTTPS. Значения > 0.5
характерны для трафика с нетипичным распределением длин (например,
фиксированный размер фреймов VPN).

**Критерий PASS:** `kl_len < 0.30`

---

### M7 — KL-дивергенция межпакетных интервалов

**Модуль:** `tester/analyzers/flow_ml.py`  
**Вес в вердикте:** средний

Аналогично M6, но для **межпакетных интервалов** (IAT, Inter-Arrival Time).

**Эталонное распределение IAT для HTTPS:**

| Диапазон | Вероятность | Интерпретация |
|---|---|---|
| 0–1 мс | 0.38 | Пакеты одного TLS-записа |
| 1–5 мс | 0.15 | |
| 5–20 мс | 0.15 | Стандартный RTT LAN |
| 20–100 мс | 0.15 | RTT WAN |
| 100–500 мс | 0.12 | Think-time пользователя |
| > 500 мс | 0.05 | Долгие паузы |

VPN-туннели часто имеют более равномерные IAT (постоянный keep-alive)
или характерные пики при bursting, что даёт высокое значение KL.

**Критерий PASS:** `kl_iat < 0.30`

---

### M8 — Активное зондирование

**Модуль:** `tester/analyzers/probe.py`  
**Инструмент:** прямые TCP-соединения  
**Вес в вердикте:** высокий

Отправляет пять типов специально сформированных запросов на TCP-порт
туннельного сервера и анализирует поведение ответов.

**Пять типов зондов:**

| Зонд | Описание |
|---|---|
| `random_bytes` | 32 случайных байта |
| `partial_tls` | Обрезанный TLS-заголовок (5 байт, объявляет 256 байт данных) |
| `valid_tls_hello` | Корректный TLS 1.3 ClientHello с SNI |
| `http_get` | Валидный HTTP/1.1 GET-запрос |
| `empty_connect` | Соединяется, ничего не отправляет |

**Три проверки различимости:**

| Проверка | Условие срабатывания | Логика |
|---|---|---|
| C1 | Сервер ответил на случайные байты | Настоящий TLS-сервер молчит или закрывает соединение |
| C2 | Сервер не ответил на HTTP GET строкой `HTTP/...` | Настоящий HTTPS-сервер всегда отвечает |
| C3 | Сервер первым начал говорить (при пустом соединении) | HTTPS-сервер ждёт ClientHello |

`distinguishable_ratio = (число сработавших проверок) / 3`

Идеальный туннель: `0.0` (0 из 3 проверок сработало).  
Явно детектируемый: `1.0` (все 3 сработали).

**Метрики на выходе:**

| Поле | Описание |
|---|---|
| `distinguishable_ratio` | [0.0, 1.0], 0.0 — неотличим |
| `distinguishable_flags` | Число сработавших проверок (0–3) |
| `check_random_bytes_responded` | Ответил ли сервер на мусор |
| `check_http_looks_http` | Является ли ответ на GET корректным HTTP |
| `check_server_speaks_first` | Говорит ли сервер первым |
| `ttfb_mean_ms` | Среднее TTFB по всем зондам (мс) |
| `ttfb_values_ms` | Массив TTFB по каждому зонду |
| `probe_count` | Число выполненных зондов |

Сырые результаты каждого зонда сохраняются в `probe_results.json`.

**Критерий PASS:** `distinguishable_ratio < 0.67` (не более 1 проверки из 3)

---

## Трафик-сценарии

### `web` (по умолчанию)

Повторяет HTTP GET-запросы к нескольким хостам через SOCKS5-прокси.
Имитирует обычный браузерный веб-сёрфинг.

- Использует `requests` + `PySocks` (если установлены)
- Fallback: сырой SOCKS5 без зависимостей
- Хосты: `example.com`, `example.org`, `httpbin.org/get`, `httpbin.org/headers`
- Пауза между запросами: 300 мс

### `bulk`

Непрерывная загрузка больших блоков данных (512 КБ за раз через httpbin).
Нагружает фреймирование и паддинг туннеля.

### `idle`

Открывает одно TCP-соединение и держит его живым в течение всей длительности
теста. Позволяет проверить keep-alive механизм туннеля и поведение при
минимальном трафике.

---

## Выходные артефакты

Все файлы записываются в `--output`:

```
results/run-01/
│
├── report.json              # итоговый отчёт (PASS/FAIL + все метрики)
│
├── capture.pcap             # сырой дамп сетевого трафика
│
├── probe_results.json       # M8: сырые ответы на каждый зонд
│   {
│     "random_bytes":   {"connected": true, "responded": false, "silent": true},
│     "partial_tls":    {"connected": true, "responded": false, "rst": true},
│     "valid_tls_hello":{"connected": true, "responded": true,  "ttfb_ms": 12.3, ...},
│     "http_get":       {"connected": true, "responded": true,  "looks_like_http": true, ...},
│     "empty_connect":  {"connected": true, "server_speaks_first": false}
│   }
│
├── flow_features.csv        # M4/M5: признаки потоков (для обучения ML)
│   duration_s, fwd_pkts, bwd_pkts, byte_ratio, all_len_mean, ...
│
├── ndpi_flows.csv           # M1: per-flow CSV от ndpiReader (-C)
│   # Столбцы: ndpi_proto, ja3c, ja3s, server_name_sni, tls_version, ...
│
├── ndpi_summary.txt         # M1: текстовая сводка ndpiReader (-w)
│
├── suricata/
│   └── eve.json             # M2: EVE-лог Suricata (JSON-lines)
│
├── zeek/
│   ├── ssl.log              # M3: TLS-сессии (TSV)
│   ├── conn.log             # M3: TCP-соединения (TSV)
│   └── ...                  # files.log, http.log, tunnel.log и др.
│
└── zeek_scripts/
    └── local.zeek           # встроенный Zeek-скрипт (монтируется :ro)
```

---

## Формат отчёта

`report.json` имеет следующую структуру:

```jsonc
{
  // Итоговый вердикт
  "verdict": "PASS",          // "PASS" или "FAIL"

  // Списки ключей чеков из раздела "checks"
  "failed_checks":  [],
  "skipped_checks": ["M1_ndpi"],   // Docker недоступен и т. п.

  // Детализация по каждой метрике
  "checks": {
    "M1_ndpi": {
      "result": "SKIP",
      "detail": { "reason": "docker_unavailable" }
    },
    "M2_suricata": {
      "result": "PASS",
      "detail": { "alert_count": 0, "categories": [] }
    },
    "M3_ja3": {
      "result": "PASS",
      "detail": {
        "ja3_is_browser": true,
        "browser_matches": ["Firefox-120"],
        "unique_ja3_count": 1,
        "high_entropy_streams": 0,
        "payload_byte_entropy": 7.718
      }
    },
    "M4_vpn_prob": {
      "result": "PASS",
      "detail": { "vpn_prob": 0.312 }
    },
    "M5_vpn_prob_seq": {
      "result": "PASS",
      "detail": { "vpn_prob_seq": 0.28 }
    },
    "M6_kl_len": {
      "result": "PASS",
      "detail": { "kl_len": 0.118 }
    },
    "M7_kl_iat": {
      "result": "PASS",
      "detail": { "kl_iat": 0.093 }
    },
    "M8_probe": {
      "result": "PASS",
      "detail": { "distinguishable_ratio": 0.0, "flags": 0 }
    }
  },

  // Параметры запуска
  "config": {
    "dsl_config":  "/path/to/example.yaml",
    "scenario":    "web",
    "duration_s":  30
  },

  // Сырые данные от каждого анализатора (полные словари)
  "raw": {
    "pcap_path":   "/path/to/capture.pcap",
    "m1_ndpi":     { ... },
    "m2_suricata": { ... },
    "m3_zeek":     { ... },
    "m4_m7_flow":  { ... },
    "m8_probe":    { ... }
  }
}
```

---

## Логика вердикта

Вердикт **PASS** выставляется только если **все** не-SKIP проверки прошли:

| Чек | Условие PASS | Порог |
|---|---|---|
| `M1_ndpi` | `is_known_vpn == False` | — |
| `M2_suricata` | `alert_count == 0` | 0 алертов |
| `M3_ja3` | `ja3_is_browser == True` ИЛИ (`unique_ja3_count == 0` И `high_entropy_streams == 0`) | — |
| `M4_vpn_prob` | `vpn_prob < 0.65` | 65% |
| `M5_vpn_prob_seq` | `vpn_prob_seq < 0.65` | 65% |
| `M6_kl_len` | `kl_len < 0.30` | 0.30 нат |
| `M7_kl_iat` | `kl_iat < 0.30` | 0.30 нат |
| `M8_probe` | `distinguishable_ratio < 0.67` | ≤ 1 из 3 |

Чек получает результат **SKIP** если:
- Анализатор вернул `{"skipped": True, ...}` (Docker недоступен, образ не найден)
- Анализатор вернул `{"error": "..."}` (упал с исключением)

Пропущенные чеки **не влияют** на вердикт.

---

## Настройка порогов

Пороги вынесены в константы в начале `tester/report.py`:

```python
_VPN_PROB_THRESHOLD   = 0.65   # M4 и M5
_KL_THRESHOLD         = 0.30   # M6 и M7
_DIST_RATIO_THRESHOLD = 0.67   # M8 (2/3)
_SURICATA_ALERT_MAX   = 0      # M2
```

Для более мягкого тестирования на ранних стадиях разработки можно поднять пороги:

```python
_VPN_PROB_THRESHOLD   = 0.80
_KL_THRESHOLD         = 0.50
_DIST_RATIO_THRESHOLD = 1.01   # фактически отключает M8
```

---

## ML-модель для M4

По умолчанию M4 использует эвристический классификатор. Для замены на
реальную sklearn-модель:

### 1. Собрать датасет

Запустите тест с несколькими конфигами и соберите `flow_features.csv`:

```bash
for cfg in configs/*.yaml; do
  python run_test.py --config "$cfg" --root ../tunnel-gen \
    --output "./results/$(basename $cfg .yaml)" \
    --scenario web --duration 60
done
```

### 2. Разметить данные и обучить модель

```python
import pandas as pd
import pickle
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split

# Собрать все CSV с метками (1 = VPN, 0 = HTTPS)
dfs = []
for path, label in [("results/vpn/flow_features.csv", 1),
                     ("results/https/flow_features.csv", 0)]:
    df = pd.read_csv(path)
    df["label"] = label
    dfs.append(df)

data = pd.concat(dfs)
X = data.drop("label", axis=1)
y = data["label"]

model = GradientBoostingClassifier(n_estimators=200, max_depth=4)
model.fit(X, y)

with open("results/model.pkl", "wb") as f:
    pickle.dump(model, f)
```

### 3. Использовать модель

Поместите `model.pkl` в **родительскую директорию** относительно `--output`:

```
results/
  model.pkl        ← здесь
  run-01/
    report.json
    ...
```

Модель будет подхвачена автоматически. Поле `model_used` в отчёте
изменится с `"heuristic"` на `"sklearn"`.

---

## Кастомные правила Suricata

Файл `rules/custom.rules` загружается при каждом запуске Suricata
вместе с ET Open. Формат — стандартный Snort/Suricata.

Используйте диапазон SID `9000001–9000099` (зарезервирован для локальных правил).

Пример добавления правила под конкретный туннель:

```
# Обнаружение Noise Protocol по паттерну рукопожатия NN
alert tcp any any -> any 7000 (
    msg:"CUSTOM Noise Protocol NN handshake";
    flow:established,to_server;
    content:"|00 20|"; depth:3;
    content:"|00 20|"; distance:32; within:35;
    classtype:policy-violation;
    sid:9000010; rev:1;
)
```

После правки правил повторный запуск автоматически их подберёт — кеша Suricata нет.

---

## Docker-образ nDPI

`ndpiReader` нет в публичном Docker Hub, поэтому образ собирается из `docker/ndpi/`.

```bash
# Сборка (занимает 2–5 минут, требует интернет для загрузки ntop-репо)
docker build -t tunnel-testing/ndpi:latest docker/ndpi/

# Проверка — должна напечатать версию ndpiReader
docker run --rm tunnel-testing/ndpi:latest --version
```

### Содержимое образа

| Файл | Описание |
|---|---|
| `Dockerfile` | Ubuntu 22.04, устанавливает `libndpi-bin` из `apt-ntop-stable` |
| `pcap_normalize.py` | Конвертирует DLT_NULL → DLT_RAW (снимает 4-байтовый Windows AF-заголовок) |
| `ndpi_entrypoint.sh` | Обёртка: вызывает `pcap_normalize.py` перед `ndpiReader` при обнаружении DLT_NULL |

### Почему нужна нормализация PCAP?

На Windows tcpdump захватывает loopback-трафик в формате **DLT_NULL** (link type 0).
Каждый пакет предваряется 4-байтовым заголовком с семейством адресов (`02 00 00 00` = AF_INET).
ndpiReader 4.x не понимает DLT_NULL и молча пропускает все пакеты, выдавая пустой результат.
`pcap_normalize.py` патчирует заголовок файла (`linktype 0 → 101`) и снимает
4-байтовый AF-заголовок с каждого пакета. Файл в формате DLT_ETHERNET или DLT_RAW
передаётся без изменений.

### Имя пакета

В 2024 году ntop переименовал пакет:

| Старое имя | Новое имя |
|---|---|
| `ndpi-tools` | `libndpi-bin` |

Если образ был собран до этого изменения, его необходимо пересобрать:
```bash
docker rmi tunnel-testing/ndpi:latest
docker build --no-cache -t tunnel-testing/ndpi:latest docker/ndpi/
```

### Флаг `-J` (JSON) в ndpiReader 4.2

Флаг `-J` в ndpiReader 4.2 сломан: вызывает вывод справки и `exit 1`.
Вместо него используется `-C <path>` (per-flow CSV) — он даёт более богатые
данные: протокол, JA3/JA3S хэши, SNI, версия TLS, байт-счётчики на поток.

---

## Сравнение конфигураций (compare.py)

`compare.py` выводит сводную таблицу результатов для нескольких конфигов
туннеля, запущенных через `run_test.py`.

```bash
python compare.py results/baseline/ results/noise-ik/ results/tls-token/
```

Пример вывода:

```
Config            M1 nDPI   M2 IDS  M3 JA3/ent  M4 prob  M5 seq   M6 KL-len  M7 KL-iat  M8 probe  Verdict
────────────────  ────────  ──────  ──────────  ───────  ──────   ─────────  ─────────  ────────  ───────
baseline-plain    ✓TLS      ✓       ✓ja3-ok     ✓0.31    ✓0.28    ✓0.11      ✓0.09      ✓0.00     PASS
noise-ik-tls      ✓TLS      ✓       ✓ja3-ok     ✓0.35    ✓0.33    ✓0.19      ✓0.12      ✓0.00     PASS
detectable-noise  ✓Unknown  ✓       ✗ent=7.85   ✗0.78    ✗0.91    ✗0.82      ✓0.11      ✗1.00     FAIL
```

Описание колонок:

| Колонка | Источник | Формат |
|---|---|---|
| `M1 nDPI` | `classified_as` | `✓TLS`, `✗OpenVPN` |
| `M2 IDS` | `alert_count` | `✓` / `✗N` (N алертов) |
| `M3 JA3/ent` | `ja3_is_browser` + `high_entropy_streams` | `✓ja3-ok`, `✗ent=7.85` |
| `M4 prob` | `vpn_prob` | `✓0.31` / `✗0.78` |
| `M5 seq` | `vpn_prob_seq` | аналогично M4 |
| `M6 KL-len` | `kl_len` | `✓0.11` / `✗0.82` |
| `M7 KL-iat` | `kl_iat` | аналогично M6 |
| `M8 probe` | `distinguishable_ratio` | `✓0.00` / `✗1.00` |

**Формат M3:** при наличии JA3-хэшей показывает `ja3-ok`/`ja3-bad`; при
отсутствии JA3 — энтропию (`ent=X.XX`), если она указывает на детектирование.

---

## Расширение фреймворка

### Добавить новый анализатор

1. Создать файл `tester/analyzers/my_metric.py`:

```python
from pathlib import Path

def analyze(pcap_path: Path, output_dir: Path) -> dict:
    # ... логика ...
    return {
        "my_value": 0.42,
    }
```

2. Вызвать в `tester/runner.py` в методе `_run_analyzers`:

```python
if "my_metric" not in cfg.skip_analyzers:
    log.info("Running M9 (my_metric)…")
    from .analyzers.my_metric import analyze as my_analyze
    results["m9_my_metric"] = my_analyze(pcap_path, cfg.output_dir)
```

3. Добавить чек в `tester/report.py` в функцию `_evaluate_checks`:

```python
m9 = raw.get("m9_my_metric", {})
checks["M9_my_metric"] = _check(
    m9,
    pass_if=lambda d: d.get("my_value", 0.0) < 0.5,
    detail=lambda d: {"my_value": d.get("my_value")},
)
```

### Добавить новый трафик-сценарий

В `tester/traffic.py`:

```python
def run_video_scenario(socks5_addr: str, duration: int, output_dir: Path) -> None:
    """Имитация потокового видео."""
    ...
```

В `tester/runner.py`:

```python
elif cfg.scenario == "video":
    from .traffic import run_video_scenario
    run_video_scenario(cfg.socks5_addr, cfg.duration, cfg.output_dir)
```

---

## Структура проекта

```
tunnel-testing/
│
├── run_test.py                  # CLI-точка входа
├── requirements.txt             # Python-зависимости
├── README.md                    # этот файл
│
├── rules/
│   └── custom.rules             # кастомные Suricata-правила (SID 9000001+)
│
├── compare.py                   # таблица сравнения нескольких прогонов
│
├── docker/
│   └── ndpi/
│       ├── Dockerfile           # сборка tunnel-testing/ndpi:latest
│       ├── pcap_normalize.py    # конвертация DLT_NULL → DLT_RAW
│       └── ndpi_entrypoint.sh   # обёртка: normalize + ndpiReader
│
└── tester/
    ├── __init__.py
    │
    ├── config.py                # TestConfig: все параметры одного запуска
    │   # dsl_config, tunnel_gen_root, scenario, duration, output_dir,
    │   # existing_pcap, skip_analyzers, no_start_tunnel, socks5_addr, capture_iface
    │
    ├── runner.py                # TestRunner: оркестрация стадий 1–6
    │
    ├── tunnel.py                # запуск tunnel-server + tunnel-client через subprocess
    │   # read_dsl_port()   — читает transport.port из DSL-конфига
    │   # tunnel_processes() — контекстный менеджер (build → start → stop)
    │
    ├── capture.py               # Capture: обёртка над tcpdump
    │   # start() / stop() / __enter__ / __exit__
    │
    ├── traffic.py               # генераторы трафика
    │   # run_web_scenario()   — HTTP GET через SOCKS5
    │   # run_bulk_scenario()  — загрузка больших блоков
    │   # run_idle_scenario()  — долгоживущее соединение
    │
    ├── report.py                # сборка отчёта + вердикт
    │   # build_report()  — применяет пороговые условия
    │   # save_report()   — записывает JSON + печатает таблицу
    │
    ├── analyzers/
    │   ├── __init__.py
    │   ├── ndpi.py              # M1: nDPI DPI-классификация (Docker, CSV-вывод)
    │   ├── suricata.py          # M2: Suricata IDS (Docker + ET Open rules)
    │   ├── zeek.py              # M3: Zeek JA3 + Python-энтропия (Docker)
    │   ├── flow_ml.py           # M4: vpn_prob  M5: vpn_prob_seq
    │   │                        # M6: kl_len    M7: kl_iat
    │   └── probe.py             # M8: активное зондирование (5 зондов, 3 проверки)
    │
    └── utils/
        ├── __init__.py
        ├── docker_run.py        # docker_run() + docker_available() + pull_if_missing()
        └── pcap_parse.py        # parse_pcap() + extract_flows() + extract_features()
                                 # Packet / Flow dataclasses
                                 # scapy (primary) + struct (fallback)
```

---

## Справка по CLI

```
usage: run_test.py [-h]
                   --config PATH
                   --root PATH
                   [--scenario {web,bulk,idle}]
                   [--duration SECS]
                   [--socks5 HOST:PORT]
                   [--iface IFACE]
                   [--pcap PATH]
                   [--no-tunnel]
                   [--skip [ANALYZER ...]]
                   [--only [ANALYZER ...]]
                   [--output PATH]
                   [--log-level {DEBUG,INFO,WARNING,ERROR}]

Обязательные аргументы:
  --config PATH, -c PATH
        Путь к DSL-конфигу tunnel-gen (.yaml)
  --root PATH, -r PATH
        Корень репозитория tunnel-gen (для go build)

Трафик:
  --scenario {web,bulk,idle}   Сценарий (по умолчанию: web)
  --duration SECS, -d SECS     Длительность в секундах (по умолчанию: 30)
  --socks5 HOST:PORT           SOCKS5-прокси (по умолчанию: 127.0.0.1:1080)
  --iface IFACE, -i IFACE      Сетевой интерфейс для tcpdump (по умолчанию: lo)

PCAP:
  --pcap PATH       Использовать готовый PCAP вместо захвата
  --no-tunnel       Не запускать tunnel-server/client

Анализаторы:
  --skip ANALYZER [...]   Пропустить: ndpi suricata zeek flow_ml probe
  --only ANALYZER [...]   Запустить только указанные (отменяет --skip)

Вывод:
  --output PATH, -o PATH         Директория результатов (по умолчанию: ./results)
  --log-level {DEBUG,INFO,...}   Уровень логов (по умолчанию: INFO)

Коды возврата:
  0  — PASS (туннель не обнаружен)
  1  — Ошибка запуска
  2  — FAIL (туннель обнаружен одним или более анализаторов)
```
