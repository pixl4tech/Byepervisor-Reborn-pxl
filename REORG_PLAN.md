# План: реорганизация репозитория + билд-варианты + тесты + GitHub/CI

Дата: 2026-10-17 · Статус: **СОГЛАСОВАНО** (private, v0.1.0, tools→gitignore+README,
standalone=автономно, audit→scripts, все -O0, ELF в build/, fresh init 1 коммит)
· Реализация — идёт

## 0. Контекст и текущее состояние

| Факт | Значение |
|---|---|
| Репозиторий | `pixl4tech/Byepervisor-Reborn` (форк `PS5Dev/Byepervisor-Reborn`), 1 коммит в своём git |
| Эксплойт | 11.60 regular, strike 16/16 проверен в бою, xotext побеждён |
| ELF | `byepervisor_reborn.elf`, 211960 байт, `sha256 3a4397b1...` |
| SDK | `sdk/ps5-payload-sdk` (34М) + `sdk/llvm18` (1.7Г) — **в git не влезает** |
| Ссылочный репо | `tools/ps5-hv-bypass-porting/` (520К) — **вложенный git** (`gzimbric/ps5-hv-bypass-porting`) |
| Мусор в дереве | `ps5-run-logs/` (22 файла), `__pycache__/`, `.trunk/{logs,out,notifications}`, `break_hv_payload/*.{o,bin,elf}` |
| Скрипты | `scripts/ps5_run.py` (лаунчер/дебаг), `scripts/audit_11_60.py` (стат. аудит) |
| MD-документы | `ANALYSIS.md`, `ANALYSIS_RU.md`, `PORTING_TOOLKIT_ANALYSIS.md`, `PORT_11_60_PLAN.md`, `TEST_11_60_PROCEDURE.md`, `scripts/ps5_run.md`, `README.md` |
| GitHub | gh CLI авторизован (`pixl4tech`), создание репо/реализов возможно локально |

## 1. Требования (декомпозиция)

| # | Требование | Интерпретация |
|---|---|---|
| R1 | Прибраться, лишний в .gitignore | SDK, логи, артефакты, кэши — вне git; bootstrap-скрипт для SDK |
| R2 | Билд без дебага на USB | Вариант `release`: `elog` без файлов на USB (stdout + уведомления остаются) |
| R3 | Автономный билд без листнера на ноуте | Вариант `standalone`: payload доводит цикл сам, stdout non-blocking (не виснет без хоста), вердикты — на-экран уведомлениями, хост не требуется |
| R4 | Тесты разных вариантов + проверка билдов | Юнит-тесты (mock elfldr, verdict-логика, аудит ELF) + live: debug — скриптом, остальные — вручную пользователем |
| R5 | Отдельный каталог билдов | `build/<variant>/` |
| R6 | Имя проекта с постфиксом pxl + версионирование | Новый репо `Byepervisor-Reborn-pxl`; `VERSION` в Makefile, версия в баннере/именах ELF/тегах |
| R7 | Реорганизация каталогов/документации | Анализ-MD → `analysis/`; англо-доки → `docs/` (структурировано) |
| R8 | Английский README | Что делает реализация, что делают скрипты, все ссылки на источники + благодарности |
| R9 | Новый GitHub проект/репозиторий | `gh repo create` + пуш |
| R10 | CI/CD | GitHub Actions: CI (тесты+сборка) и Release (ELF-варианты + скрипт по тегу `v*`) |

## 2. Целевая структура репозитория

```
Byepervisor-Reborn-pxl/
├── README.md                    # англ.: проект, варианты, скрипты, credits, ссылки
├── Makefile                     # VERSION, VARIANT=debug|release|standalone, build/<variant>/
├── .gitignore                   # обновлённый
├── main.c kdlsym.c khook.c h1160.c elog.c paging.c util.c
├── include/                     # без изменений (+ include/version.h генерируется)
├── break_hv_payload/            # без изменений (артефакты в gitignore)
├── scripts/
│   ├── ps5_run.py               # лаунчер/стрим/verdict (без изменений функционально)
│   ├── audit_11_60.py           # стат. аудит (перенос в tests/? — см. Q5)
│   └── bootstrap_sdk.sh         # НОВОЕ: скачивает SDK + LLVM в sdk/
├── build/                       # НОВОЕ (gitignored): build/debug|release|standalone/*.elf
├── tests/                       # НОВОЕ
│   ├── mock_elfldr.py           # из /tmp, доработанный (сценарии: success/armfail/drop/quiet)
│   ├── test_ps5_run.py          # verdict-логика + reconnect на mock
│   ├── test_builds.py           # сборка 3 вариантов, валидация ELF (magic, версия, строки)
│   └── live_test_checklist.md   # пошаговый live-тест (debug — скриптом; release/standalone — вручную)
├── analysis/                    # НОВОЕ: аналитические MD (ANALYSIS*.md, PORT*_*.md, TEST_11_60_PROCEDURE.md)
├── docs/                        # НОВОЕ: английская документация
│   ├── README.md                # индекс
│   ├── architecture.md          # цепочка эксплойта, hook-дизайн, TSS/IST6, cave-геометрия
│   ├── build.md                 # SDK bootstrap, варианты билда, версионирование
│   ├── network-run.md           # ps5_run.py (перенос ps5_run.md, англ.)
│   ├── standalone-run.md        # автономный запуск без Мака
│   └── testing.md               # юнит + live, чек-листы
├── tools/ps5-hv-bypass-porting/ # см. Q3 (submodule | vendor | ignore)
├── sdk/                         # gitignored, через bootstrap_sdk.sh
└── .github/workflows/
    ├── ci.yml                   # push: bootstrap SDK, build x3, тесты, артефакты
    └── release.yml              # tag v*: release с ELF x3 + ps5_run.py + README
```

## 3. Билд-варианты (R2, R3, R5, R6)

### 3.1 Матрица

| | `debug` (по умолчанию) | `release` | `standalone` |
|---|---|---|---|
| USB-лог (`elog` файл) | ✅ | ❌ | ❌ |
| Стрим в stdout/TCP | ✅ (block) | ✅ (block) | ✅ (**non-blocking**) |
| Уведомления на экране | ✅ | ✅ | ✅ |
| Heartbeat 30с | ✅ | ✅ | ✅ |
| Зависимость от хоста | да (для логов) | опционально | **нет** |
| Вердикт | стрим + экран | стрим + экран | **только экран** |
| Имя артефакта | `build/debug/byepv-pxl-v<ver>.elf` | `build/release/...` | `build/standalone/...` |

### 3.2 Механика (C-изменения)

1. `elog.c`:
   - `elog_init()`: при `PXEL_NO_USB` (release/standalone) не открывать файл; terminal marker
     остаётся на stdout (нужен скрипту в debug/release).
   - `PXEL_STANDALONE`: `fcntl(STDOUT_FILENO, F_SETFL, O_NONBLOCK)` — запись в stdout
     никогда не блокирует payload (хост умер → строки теряются, процесс жив).
   - Стрим «previous run log» из USB — только в `debug`.
2. `main.c`:
   - Баннер: `Byepervisor-pxl v<MAJOR.MINOR.PATCH> (<variant>)` — версия из
     `include/version.h` (генерируется Makefile из `VERSION`).
   - Все ключевые вердикты дублируются `elog_notify` (для standalone они — единственный канал).
3. `Makefile`:
   - `VERSION ?= 0.1.0` (см. Q2), `VARIANT ?= debug`.
   - `CFLAGS += -DPXEL_$(VARIANT_UPPER)` (+ `-O2` для release/standalone? — см. Q6,
     по умолчанию оставляем `-O0` — hook чувствителен, -O0 проверен).
   - Цели: `all` (debug), `release`, `standalone`, `all-variants`, `clean`,
     `test` (запуск python-тестов), `bootstrap` (SDK).
   - Артефакты → `build/<variant>/byepv-pxl-v$(VERSION).elf`; корневой `byepervisor_reborn.elf`
     оставляем как symlink/копию для обратной совместимости с текущим скриптом (или меняем
     `--elf` по умолчанию — см. Q7).

## 4. .gitignore (R1)

```
sdk/
build/
ps5-run-logs/
*.elf            # кроме build/ (и так вне git)
*.o
break_hv_payload/break_hv.{bin,elf,o}
__pycache__/
*.pyc
.trunk/logs/ .trunk/out/ .trunk/notifications/
.DS_Store
```
+ `scripts/bootstrap_sdk.sh`: скачивает `ps5-payload-sdk` v0.44
(`github.com/ps5-payload-dev/sdk/releases/download/v0.44/ps5-payload-sdk.zip`)
и LLVM 18.1.8 bottle (arm64_sonoma, sha256 закреплён), патчит install names +
ad-hoc codesign (весь сегодняшний процесс автоматизирован), идемпотентен.

## 5. Тесты (R4)

### 5.1 Автоматические (локально и в CI)

| Тест | Что проверяет |
|---|---|
| `tests/test_builds.py` | сборка всех 3 вариантов; ELF magic/архитектура; строка версии в ELF; в release/standalone **нет** строк `/mnt/usb0`/`byepv960`; в debug — есть; размеры в sanity-диапазоне |
| `tests/test_ps5_run.py` | verdict-логика на mock-потоках: SUCCESS (включая "already compromised"), ARM_FAIL, clean-exit без resend, EOF без маркера → reconnect+resend, silence gap → rest mode; запись mac-лога |
| `tests/mock_elfldr.py` | mock elfldr: приём ELF, SHUT_WR, стрим сценария (успех/сбой/обрыв/тишина), параметризуем сценарий флагом |
| `scripts/audit_11_60.py` | существующий стат. аудит — в прогон (регресс-маркер) |

### 5.2 Live-тесты (чек-лист `tests/live_test_checklist.md`)

1. **debug** (делаем мы, через скрипт): `python3 scripts/ps5_run.py` →
   ожидаем полный цикл стрима + `verdict=SUCCESS` (или ARM_FAIL с дамптом) +
   лог в `ps5-run-logs/`. Проверяем: стрим реал-тайм, previous-log-дамп,
   terminal marker, нет зацикливания.
2. **release** (вручную, пользователь): отправить `build/release/*.elf`
   любым способом (nc/свой лоадер) → на консоли уведомления по фазам,
   на USB файлов НЕТ, цикл завершается (уведомление SUCCESS/FAIL).
3. **standalone** (вручную, пользователь): то же, **без Мака в сети**
   (кабель можно не держать после загрузки ELF) → payload доводит цикл сам,
   не виснет на stdout, вердикт — уведомлением.

## 6. Документация (R7, R8)

- `analysis/`: `ANALYSIS.md`, `ANALYSIS_RU.md`, `PORTING_TOOLKIT_ANALYSIS.md`,
  `PORT_11_60_PLAN.md`, `TEST_11_60_PROCEDURE.md` (перенос как есть).
- `docs/` (англ., новая): `README.md` (индекс), `architecture.md`, `build.md`,
  `network-run.md` (перенос+перевод `scripts/ps5_run.md`), `standalone-run.md`, `testing.md`.
- `scripts/ps5_run.md` → удалить (замещён `docs/network-run.md`), в скрипте
  комментарий-ссылка.
- `README.md` (корень, англ.):
  - что это: HV-bypass эксплойт 11.60 regular (xotext + 16×VMCB strike), статус «проверен в бою»;
  - таблица билд-вариантов;
  - быстрый старт (bootstrap → make → скрипт);
  - описание `ps5_run.py` и `audit_11_60.py`;
  - ссылки и благодарности:
    - `PS5Dev/Byepervisor-Reborn` (upstream, John Törnblom и соавторы) — базовая реализация;
    - `gzimbric/ps5-hv-bypass-porting` (+ `gzimbric/Byepervisor-Reborn` commit 340ed30) —
      валидированный 11.60 production-порт и porting toolkit;
    - `ps5-payload-dev/sdk` v0.44 (John Törnblom / сообщество) — SDK;
    - Homebrew `llvm@18` 18.1.8 — toolchain;
    - `relapse` kernel-цепочка + `elfldr` (TCP 9021) — доставка.

## 7. GitHub (R9)

1. `gh repo create pixl4tech/Byepervisor-Reborn-pxl` (видимость — Q1).
2. Новый git-репо (fresh init, история: 1 коммит «byepv-pxl v0.1.0 — ...»
   или перенос истории — Q8), remote → новый репо.
3. Старый `pixl4tech/Byepervisor-Reborn` не трогаем.
4. Первый тег `v0.1.0` → запускает release-workflow.

## 8. CI/CD (R10)

### `ci.yml` (on: push, pull_request)
- runner: `macos-14` (arm64) — нужен Homebrew LLVM 18 + zstd;
- шаги: checkout → `scripts/bootstrap_sdk.sh` (кэшируем `sdk/` по sha) →
  `make all-variants` → `python3 -m pytest tests/ -q` (или `unittest`) →
  `scripts/audit_11_60.py` → upload артефактов (3 ELF + скрипты).

### `release.yml` (on: tags `v*`)
- та же сборка;
- `softprops/action-gh-release`: ассеты
  `byepv-pxl-v<ver>-{debug,release,standalone}.elf`,
  `ps5_run.py`, `ps5_run.md`/`docs/network-run.md`, `README.md`,
  `SHA256SUMS`;
- тело релиза: версия, changelog (из git log), таблица вариантов, quick start.

## 9. Порядок работ (фазы с гейтами)

| Фаза | Содержание | Гейт |
|---|---|---|
| **F1** | C-изменения: version.h, elog-варианты, Makefile (VARIANT, build/), .gitignore, bootstrap_sdk.sh | `make all-variants` локально, 3 ELF в `build/` |
| **F2** | Тесты: tests/ (mock, test_ps5_run, test_builds), перенос audit | `python3 -m unittest` зелёно локально |
| **F3** | **Live-тест debug через скрипт** (консоль+кабель) | `verdict=SUCCESS` в mac-логе |
| **F4** | Реорганизация: analysis/, docs/, README.md (англ.), удаление старого ps5_run.md | дерево по п.2 |
| **F5** | GitHub: новый репо, пуш, тег v0.1.0 | репо онлайн |
| **F6** | CI/CD: ci.yml + release.yml, первый зелёный CI-ран, первый релиз | релиз с ассетами |
| **F7** | Live-тест release/standalone (пользователь, вручную) | чек-лист закрыт |

## 10. Риски

| Риск | Митигция |
|---|---|
| `-O2` сломает hook (inline asm, noinline-границы) | по умолчанию `-O0` во всех вариантах (Q6) |
| non-blocking stdout: EINTR/EAGAIN в elog | проверка `errno==EAGAIN` → строку пропустить, не умирать |
| CI macos-14 + LLVM 18 bottle недоступен | fallback: `brew install llvm@18` или кэш SDK-артефакта в репо-actions-cache |
| Вложенный git в tools/ ломает git-операции | решение Q3 до F5 |
| Потеря текущего ELF при переносе | sha256 в Makefile-комментарий + артефакт CI |

## 11. Вопросы для согласования

1. **Видимость нового репо**: public или private?
2. **Стартовая версия**: `v0.1.0` (research) или `v1.0.0` (рабочий эксплойт)?
3. **`tools/ps5-hv-bypass-porting/`** (вложенный git, 520К): (a) git submodule, (b) vendor (убрать вложенный .git, коммитнуть файлы), (c) gitignore + bootstrap?
4. **Standalone**: верно ли понимание — «payload сам доводит цикл, stdout non-blocking, вердикт только уведомлениями, Мака можно вообще не включать после загрузки ELF»?
5. **`audit_11_60.py`**: оставить в `scripts/` или перенести в `tests/`?
6. **Оптимизация**: release/standalone тоже `-O0` (безопасно, проверено) или попробовать `-O2` (риск)?
7. **Имя ELF**: `byepv-pxl-v<ver>.elf` (новые) + корневой `byepervisor_reborn.elf` убрать после перехода, или держать оба?
8. **История git** в новом репо: fresh init (1 коммит) или перенос всей истории (rebase на новый remote)?
