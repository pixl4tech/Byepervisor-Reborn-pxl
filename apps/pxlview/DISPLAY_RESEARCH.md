# pxlview Display Research — PS5 11.60, WebKit payload → HDMI

Цель: вывести UI приложения pxlview (WebKit payload) на внешний HDMI-монитор PS5.

## 0. Среда

- PS5, firmware 11.60 regular
- HV bypass через relapse (перезапускается после ребоута), elfldr на TCP 9021
- pxlview = WebKit payload (инжектится в контекст процесса WebKit)
- Внешний HDMI-монитор (не ТВ), пульта нет
- SDL2 статическая, патч `patches/sdl2-ps5-videout-open.patch`
- Запуск: `python3 scripts/ps5_run.py --elf apps/pxlview/build/pxlview-{latest,diag}.elf --no-setup`

## 1. Что уже РАБОТАЕТ

| Компонент | Статус |
|---|---|
| Kernel access (authid 0x480000001000000e → 0x4800000000000007, save/restore) | ✅ |
| Сборка панелей: procs=48, /mnt/rnps (ufs.ver/env/rev, apps), p_comm @ +0x5dc | ✅ |
| SDL_CreateWindow 1920x1080 (fmt=0x16762004) | ✅ |
| `sceVideoOutOpen(0xff, 2, 0, NULL)` | ✅ |
| 2×16M `sceKernelAllocateMainDirectMemory` + map | ✅ |
| `sceVideoOutRegisterBuffers2` (2 буфера) | ✅ |
| `sceVideoOutSubmitFlip` (драйвер принимает) | ✅ |
| `kernel_copyout` / `kernel_setlong` на kernel heap | ✅ |
| `kernel_get_proc_file(pid, fd)` | ✅ (но мусорит на свободных fd) |
| `kill(pid, 9)` VSH-процессов | ✅ |

## 2. Главная проблема

**Flip'ы уходят в драйвер, но на HDMI-монитор не попадают.** На мониторе — картинка VSH (меню). pxlview для видеоподсистемы — «второстепенный» клиент.

## 3. Все эксперименты и результаты

### 3.1 Матрица sceVideoOutOpen
- `(0xff, 0, 0)` — ок (после ребоута); flips не на монитор
- `(0xff, 2, 0)` — надёжно ок при живом VSH
- display 0 занят VSH (Device busy в части конфигураций)
- 1 буфер: register → `-2144796671` (No such process); 2 буфера: ok
- 16M×1 — мало; 32M×1 — ок один раз, потом пул забит; 64M — Resource temporarily unavailable
- **3-й `sceVideoOutOpen` в том же процессе → EINVAL** (первые два ок)

### 3.2 Flip master
- `sceVideoOutSetFlipMaster` / `sceVideoOutClearFlipMaster` → `-2144796661` (ESRCH) для любых аргументов: handle, getpid(), fd
- Вывод: механизм master привязан к чему-то, чего нет у WebKit payload

### 3.3 Sys* API
- `sceVideoOutSysGetBus` → ESRCH (0x8029000b)
- `sceVideoOutSysOpenInternal(0,0,0,0)` → err
- `sceVideoOutGetStatusForWebcore(0,0,0,0)` → 0x80290002
- Не удалось подобрать аргументы

### 3.4 Убийство pid 78 (SceVideoCore2K)
- `kill(78,9) = 0`
- **Монитор: замороженный последний кадр** (VSH-меню стоит, анимаций нет)
- Сессия mёртвого процесса ОСТАЛАСЬ в списке драйвера (self-loop по +0x8)
- VSH НЕ перезапускает pid 78
- Вывод: вывод на экран ведёт ядро/драйвер из буферов «активной» сессии, не процесс

### 3.5 Переподключение HDMI
- После выдёргивания/втыкания HDMI: **меню полностью оживло** (анимации)
- Основные сессии перерегистрировал **pid 59 (SceShellCore)**
- pid 78 так и не возродился
- Вывод: конвейер восстанавливаем; владелец отображаемой сессии — не фиксированный процесс

### 3.6 Структуры драйвера (kernel walk)
Сессия (fdata):
- `+0x08` — next (циклический список сессий драйвера)
- `+0x40..+0xf0` — 5 слотов по 0x30; слот[0] = указатель на entry-объект

Entry-объект:
- `+0x20` — тип: VSH main = `0x1_00040001`, остальные VSH = `0x2_00040001`, наша = `0x3_00000002`
- запись любого из вариантов типа: ок, сохраняется, **на дисплей не влияет**

Pipe-объект (entry[2], общий):
- `+0x58` = **system authid 0x4800000000000007** (контекст «системного» вывода)

### 3.7 List hijack
- Вставка нашей сессии после основной в список (+0x8): ок, **на дисплей не влияет**

### 3.8 Поиск фреймбуфера
- 3 уровня дерева сессии (128 объектов): ПА direct memory (0x2_0000_0000..0x3_0000_0000) не найдено (только размеры 0x200000000)
- 2MB данных `libSceVideoOut.sprx` (mapbase 0x838e94000): указатель на сессию не найден
- Кода sprx по резолвнутым адресам символов читается нулями (когда?)
- Вывод: буфер описан глубже (iommu/DMA-таблицы) или хранится иначе

### 3.9 fd-таблица
- После `sceVideoOutOpen` **новый fd в таблице процесса НЕ появляется**
- `kernel_get_proc_file` возвращает мусор на свободных fd (напр. 0x63736564656c6966)
- VSH-сессии видны в fd-таблицах pid 59/94

### 3.10 Мёртвая сессия
- fdata мёртвой сессии pid 78 читаема (0xffffb60202bd23e0), +0x08 = self
- entry0[0] объект: `+0x58` = 0x200000000 (2GB, размер), `+0xc0` = 0x10000, function ptrs
- e00+0xa8 объект: container с function ptrs, без PА буфера

## 4. Ключевые гипотезы

1. **Маршрутизация вывода сделана в «системном» контексте** (pipe имеет system authid). WebKit payload — клиент 2-го сорта; чтобы стать «master», нужно то, чего у payload нет (видимо, флаг при открытии через Sys* API или special credential).
2. **Oboot-приложение получает вывод «по праву рождения»** — система отдаёт дисплей app-процессу. WebKit payload — нет.
3. Буфер активной сессии можно найти и переписать напрямую (DMA-таблицы), но это глубокое kernel-реверс.

## 5. Что можно ещё исследовать (TODO)

### A. Semantics VideoOut API
- [ ] Точные сигнатуры и смысл аргументов: `sceVideoOutOpen`, `sceVideoOutSetFlipMaster`, `sceVideoOutSysOpenInternal`, `sceVideoOutSysGetBus`
- [ ] Что такое «flip master» на PS5 и кто его устанавливает (VSH? ядро при open с флагом?)
- [ ] Аргументы `sceVideoOutOpen(0xff, X, Y, Z)`: что 0xff, что X (0/1/2), что Y
- [ ] Есть ли флаг open, делающий сессию «primary/master»

### B. Preцеденты: кто уже выводит картинку из payload
- [ ] PS5SX2 / Oracle / PS5 Payload Manager — как они показывают UI (eboot или VideoOut?)
- [ ] PS5 WebKit-пейлоуды с визуалом (browser payloads, «PS5 WebKit UI»?)
- [ ] PS4 аналогия: как ps4-payloads (Adrenaline) выводили UI из payload-контекста (vulkan? videoout?)
- [ ] Примеры `sceVideoOutSetFlipMaster` в открытом коде (GitHub: ps5 videoout, prospero)

### C. Eboot-путь
- [ ] Минимальный eboot для PS5 (шаблон, размеры, секции)
- [ ] Как запустить eboot из payload-only окружения (PS5SX2 как launcher payload)
- [ ] NoNHS / app install на /dev_hdd0 и запуск из VSH
- [ ] Нужен ли homebrew loader или достаточно relapse+elfldr+launcher

### D. Ядро 11.60
- [ ] Реальное расположение кода libSceVideoOut.sprx (mapbase 0x838e94000 — код читается нулями)
- [ ] Глобальное состояние драйвера: где list head сессий, где «active session»
- [ ] IOMMU/DMA: как драйвер хранит ПА фреймбуфера
- [ ] ROPs: `sceVideoOutSubmitFlip` → что происходит дальше в драйвере

### E. Дисплей/AV
- [ ] `SceHdmiEvent` (pid 2): события HDMI, можно ли принудить reinit
- [ ] Смена output mode из payload (resolution change → пересборка конвейера)
- [ ] Можно ли «выпросить» у VSH смену сессии через IPC/notifications

## 6. Вопросы для интернета

1. "PS5 sceVideoOutSetFlipMaster" — кто использует, какие аргументы, что возвращает
2. "PS5 WebKit payload video out" / "PS5 webkit payload display" — выводят ли картинку
3. "PS5 eboot payload launch PS5SX2" — запуск eboot из payload
4. "PS5SX2" как работает, показывает ли UI, eboot ли
5. "PS5 libSceVideoOut.sprx" reverse / symbols
6. "PS5 videoout driver session" flip master primary output
7. PS4 аналог: "PS4 video out payload UI" (Adrenaline, ps4-sdk videoout)
8. "PS5 11.60 relapse" webkit payload limitations
9. PS5 "SceVideoCore2K" / "SceShellCore" video pipeline
10. "sceVideoOutSysOpenInternal" arguments
11. PS5 homebrew eboot template minimal
12. "PS5 direct memory" webkit payload allocation limits

## 7. Найденное в интернете

### 7.1 ⭐⭐⭐ ps5-payload-dev/elfldr — КАК запускается наш payload

Источник: https://github.com/ps5-payload-dev/elfldr (elfldr.c)

`elfldr_spawn()`:
1. `rfork_thread(RFPROC | RFCFDG | RFMEM, ...)` — **новый процесс**
2. Новый процесс делает `execve("/system/vsh/app/NPXS40112/eboot.bin")` — **SceSpZeroConf** (VSH-приложение «настройка сети», у него ЕСТЬ UI)
3. `pt_syscall(pid, 599)` (dynlib_process_needed_and_relocate)
4. Брейкпоинт (int3) в `kernel_dynlib_entry_addr(pid, 0) + 58` — **точка вызова main() eboot'а**
5. `elfldr_exec()`: привилегии (uid=0, caps=0xff×16, rootdir=kernel root, jaildir=0), загрузка нашего ELF, `r_rip = payload entry`, `r_rdi = args`

**ВЫВОД:** наш pxlview — процесс с идентичностью приложения SceSpZeroConf, НО main() eboot'а НИКОГДА не выполняется (hijack на точке вызова main). Инициализация дисплея приложения (видимо, в main или до UI-цикла) не происходит → наш VideoOut-клиент «второстепенный».

### 7.2 ⭐⭐⭐ ps5-payload-dev/websrv (бывш. john-tornblom/ps5-payload-hbldr)

- Payload-веб-сервер (порт 8080). **UI рендерится встроенным WebKit-браузером PS5**
- Homebrew: `/data/homebrew/<Name>/eboot.elf` + `sce_sys/icon0.png` + опционально `homebrew.js`
- `homebrew.js`: `main()` возвращает UI-объект {mainText, secondaryText, imgPath, onclick, options}; `ApiClient.launchApp("/fs/...elf")`, `showCarousel()`, `pickFile()`
- «Launcher PKG» — устанавливается как PS5-приложение для запуска homebrew
- Старый repo (hbldr) имел **test.c — rainbow через VideoOut** (ровно наш API-паттерн: open(0xff,0,0), 2 буфера, flip), «Sample Video», «confirmed working on 3.21 and 4.50»
- `hbldr.c`: запуск homebrew через `kernel_launch` + `kernel_set_ucred_uid` + `kernel_set_ucred_caps(0xff×16)`

### 7.3 Семантика VideoOut API (shadPS4/ChonkyStation4/ps4dev)

- `sceVideoOutOpen(userId, busType, index, param)`:
  - busType: 0 = MAIN, 5 = AUX social screen, 6 = AUX game live streaming (**2 = неизвестно, у нас работает**)
  - shadPS4: `ASSERT(busType == MAIN)`, `index != 0 → INVALID_VALUE`
  - handle: «All available handles are open» → RESOURCE_BUSY (лимит handle'ов)
- `sceVideoOutSubmitFlip(handle, bufferIndex, flipMode, flipArg)`
- `sceVideoOutConfigureOutputMode_(handle, reserved, mode, options, size_mode, size_options)` — режим вывода (HDR и т.п.)
- `sceVideoOutGetDeviceCapabilityInfo`, `sceVideoOutIsFlipPending`, `sceVideoOutUnregisterBuffers`, `sceVideoOutGetBufferLabelAddress`
- Внутренние event id: Flip=0x6, Vblank=0x7, SetMode=0x51, Position=0x58, PreVblankStart=0x59, SysVblank=0x63
- etaHEN (PS4) daemon: `sceVideoOutOpen()`, `sceVideoOutConfigureOutput()`, `sceVideoOutIsOutputSupported()` + `sceKernelSuspendProcess`
- `libSceVideoOutSecondary` — отдельный sprx (id 0x80000046)!

### 7.4 Прочее

- `ps5-payload-dev/shsrv` — telnet-сервер payload (cd, mkdir, run payloads)
- `ps5-linux-loader` — payload, запускающий Linux (есть video?)
- `itsPLK/ps5-payload-manager` — web-дашборд (PC/phone/PS5)
- `sinajet/PS5-Websrv-Payload-Menu` — меню для websrv с офлайн-кешированием
- `cy33hc/ps5-payload-loader` — «Homebrew Launcher» APP (eboot) с меню загрузки payload'ов
- psdevwiki: `libSceVideoOut` = sprx id 0x80000022

## 8. Новая главная гипотеза (H-BOOT)

**Дисплей «закладывается» при инициализации приложения (в main() eboot'а или сразу после).** Наш payload обходит main() eboot'а → дисплей не заявлен → VideoOut-сессия не маршрутизируется на HDMI.

### Эксперимент E1: вызвать main() eboot'а из payload'а
1. В pxlview: `kernel_dynlib_entry_addr(getpid(), 0)` → адрес entry eboot'а
2. На entry+58 — инструкция call main():读出 целевой адрес main
3. Запустить main() в отдельном потоке (аргументы — как у eboot: argv из elfldr args?)
4. Подождать 3–5 c (eboot инициализирует дисплей/WebKit UI)
5. Найти videoout-сессию НАШЕГО процесса (fd-таблица / список драйвера)
6. Зарегистрировать наши буферы на ЭТОЙ сессии и flip'ить
7. Наблюдать за монитором

### Эксперимент E2: свой elfldr с «поздним» hijack
- Патч elfldr: не прыгать на entry+58, а дать eboot'у дожить до появления vout-fd в процессе, потом подставить payload
- elfldr открытая (GPLv3), собирается из ps5-payload-sdk

### Эксперимент E3: web-UI через браузер (обходной путь)
- pxlview поднимает HTTP-сервер (как websrv) и показывает UI в WebKit-браузере PS5
- Нужен механизм открытия браузера на URL из payload (SceSpZeroConf сам web-based? — проверить)
- Минус: UI в браузере, а не полный экран; плюс: гарантированно видно

## 9. Следующие вопросы для интернета

1. Что делает SceSpZeroConf (NPXS40112) при старте — инициализация видео? (decomp, scene-заметки)
2. «PS5 app eboot video initialization» — как app заявляет дисплей (GNM? videoout? SceDisplay?)
3. NPXS40112 / ZeroConf app PS5 — что это за приложение, UI, webkit?
4. ps5-payload-sdk: `kernel_dynlib_entry_addr` — что возвращает для eboot-процесса
5. Можно ли запустить eboot main() из чужого потока (требования к контексту)
6. PS5 «app suspend/resume» при запуске приложения (VSH→app display handoff)
7. Примеры payloads, успешно показывающих VideoOut на 9.x–13.x (issues в ps5-payload-dev)
8. `libSceVideoOutSecondary` — для чего

## 10. Глубокий разбор websrv/hbldr (DeepWiki + исходники)

### Два пути запуска payload'а как app-процесса:

**Путь A (plain elfldr — НАШ):**
- `rfork_thread(RFPROC|RFCFDG|RFMEM)` → новый процесс
- `execve("/system/vsh/app/NPXS40112/eboot.bin")` (SceSpZeroConf)
- syscall 599 (dynlib relocate), heap=-1, int3 на `kernel_dynlib_entry_addr(pid,0)+58` (call main)
- `elfldr_exec`: привилегии (uid=0, caps=0xff×16, rootdir, jaildir=0), загрузка ELF, jump
- **Системный app-менеджер НЕ участвует**

**Путь B (websrv/hbldr):**
- `fakeapp_create_if_missing()`: создаёт FAKE00000 (клон PS Now NPXS40106) в /system_ex (remount rw); eboot.bin копируется из NPXS40112; «this binary is never executed; it merely satisfies the PS5 system's validation checks»; «must appear legitimate to the PS5 system services to be launched successfully»
- `sceSystemServiceLaunchApp("FAKE00000", argv, ctx)` в отдельном потоке (blocking call)
- ptrace на **SceSysCore.elf**: `pt_follow_fork` → дочерний процесс → `pt_follow_exec` → eboot загружен
-syscall 599, heap=-1, int3 на entry+58, замена контекста (argv0, environ, cwd, stdio через rdup 0x25b)
- привилегии как у пути A
- **Системный app-менеджер (SceSysCore) УЧАСТВУЕТ в создании процесса**

### param.json FAKE00000:
```json
{ "applicationCategoryType": 0, "attribute": 1, "attribute2": 0, "attribute3": 4,
  "titleId": "FAKE00000", "contentId": "IV9999-FAKE00000_00-HOMEBREWLOADER00",
  "localizedParameters": { "defaultLanguage": "en-US",
    "en-US": { "titleName": "Homebrew Loader" } } }
```

### Вывод для нашей проблемы
Путь B проходит через официальный app-launch → система может настроить display handoff (VSH→app) для процесса. Путь A (наш) — нет. **Кандидаты на решение:**
1. Запустить наш payload путём B (FAKE app + sceSystemServiceLaunchApp + hijack)
2. Из текущего процесса (SceSpZeroConf) вызвать main() eboot'а и дать ему «заявить» дисплей
3. Запустить настоящий NPXS40112 (ZeroConf) через систему и посмотреть, появится ли его UI (проверка handoff)

### RNPS wiki (psdevwiki.com/ps5/RNPS)
- NPXS40112 в списке НЕТ (пропуск 40111→40136) — не задокументирован
- NPXS40106 = PS Now (донор eboot для FAKE00000)
- /mnt/rnps mounted on /dev/lv0 — совпадает с тем, что мы видим в payload'е

### offact issue #13 (Black Screen in 11.20)
- Black screen при запуске homebrew через Homebrew Launcher на 11.x/12.x/13.x
- **Лечится пересборкой с SDK 0.40** («fixes starting the app on 11.x, 12.x firmwares»)
- Наши ELF собраны со своим SDK (ps5-payload-sdk из sdk/) — проверить совместимость версий

### ⭐⭐⭐ param.json (psdevwiki.com/ps5/Param.json)

**attribute3 — КЛЮЧЕВОЕ ПОЛЕ:**
| Значение | Смысл |
|---|---|
| 0 | «The application does not receive video-out info» |
| **4** | **«The application receives video-out info»** |
| 64 | HFR |
| 68 | video-out info + HFR |
| 132 | video-out info, без capture API, без HFR, без auto scaling |
| 4160 | High Framerate Mode + VRR? |

FAKE00000 имеет `attribute3: 4` → **система настраивает video-out для приложения при запуске на основании param.json!**

**applicationCategoryType:**
| Значение | Категория |
|---|---|
| 0 | Native Game |
| 65536 | Prospero Native Media App |
| 65792 | RNPS Media App |
| 66048 | Web Based Media App |
| 131328 | System Built-in App |
| 131584 | Big Daemon |
| 16777216 | ShellUI |
| 33554432 | Daemon |
| 50331648 | CommonDialog |
| 67108864 | ShellApp |

**attribute:** бит 0x20000000 = HDR, 0x40000000 = не suspend по PS-кнопке + HDCP2.2

### Следующие шаги (план)

**E3a (быстрый тест):** из payload'а вызвать `sceSystemServiceLaunchApp("NPXS40112", ...)` — запустить ZeroConf через систему. Если его UI появится на мониторе → формальный launch даёт дисплей.

**E3b (полное решение, путь B):**
1. Создать FAKE app (атрибуты как у FAKE00000, attribute3=4) на /system_ex (remount rw)
2. `sceSystemServiceLaunchApp("FAKE...", ...)` из payload'а
3. Hijack (ptrace fork/exec на SceSysCore + int3 на entry+58)
4. Запустить pxlview в этом процессе — система уже настроила video-out
5. Flip'ы должны попасть на монитор

**E1 (альтернатива):** из текущего процесса вызвать main() eboot'а NPXS40112 — он сам заявит дисплей (еслиZeroConf инициализирует видео)

## 11. Полный разбор hbldr.c (websrv @33023913) — воспроизводимая реализация

### Константы
```c
#define PSNOW_EBOOT "/system_ex/app/NPXS40106/eboot.bin"  // донор eboot
#define FAKE_PATH   "/system_ex/app/FAKE00000"
```

### remount_system_ex()
```c
struct iovec iov[] = {
  {"from", "/dev/ssd0.system_ex"}, {"fspath", "/system_ex"},
  {"fstype", "exfatfs"}, {"large", "yes"}, {"timezone", "static"},
  {"async", NULL}, {"ignoreacl", NULL}
};
nmount(iov, 7, MNT_UPDATE);  // делает /system_ex writable
```

### fakeapp_create_if_missing()
- mkdir FAKE00000, FAKE00000/sce_sys
- запись param.json (см. выше, attribute3=4!)
- копирование eboot.bin из NPXS40106 в FAKE00000/eboot.bin

### bigapp_launch(user_id, argv)
```c
parent = find_pid("SceSysCore.elf");        // sysctl KERN_PROC, name@+447, pid@+72
pt_attach(parent);
pt_follow_fork(parent);
pt_continue(parent, SIGCONT);
pthread_create(&bigapp_launch_thread);       // в потоке: sceSystemServiceLaunchApp("FAKE00000", argv, &ctx)
child = pt_await_child(parent);              // fork-событие → pid dziecka
pt_detach(parent, 0);
pt_follow_exec(child);
pt_continue(child, SIGCONT);
pt_await_exec(child);                        // exec-событие (PL_FLAG_EXEC)
pthread_join(trd, 0);                        // LaunchApp blocking
```

### app_launch_ctx_t (контекст LaunchApp)
```c
typedef struct app_launch_ctx {
  uint32_t structsize; uint32_t user_id; uint32_t app_opt;
  uint64_t crash_report; uint32_t check_flag;
  char **argv;  // extension: аргументы для потока
} app_launch_ctx_t;
```

### bigapp_replace(pid, elf, ...)
```c
pt_syscall(pid, 599);                        // dynlib_process_needed_and_relocate
elfldr_set_heap_size(pid, -1);
brkpoint = kernel_dynlib_entry_addr(pid, 0) + 58;  // call main()
kernel_mprotect(pid, brkpoint, PAGE, RWX);
int3 на brkpoint; pt_continue(SIGCONT); waitpid; restore;
bigapp_set_argv0; set_procname; set_environ; set_cwd; set_stdio(rdup 0x25b);
elfldr_exec(pid, elf);                       // привилегии + загрузка ELF + jump
```

### hbldr_launch() — оркестрация
1. fakeapp_create_if_missing (с remount при необходимости)
2. `sceUserServiceGetForegroundUser(&user_id)`
3. `sceSystemServiceGetAppIdOfRunningBigApp()` → если >0: `sceSystemServiceKillApp(app_id, -1, 0, 0)` + wait `sceKernelGetAppState`
4. read ELF → bigapp_launch → elfldr_raise_privileges → bigapp_replace

### Сигнатуры (декларации из hbldr.c)
```c
int sceSystemServiceLaunchApp(const char* title_id, char** argv, app_launch_ctx_t* ctx); // BLOCKING
int sceUserServiceInitialize(void*);
int sceUserServiceGetForegroundUser(uint32_t *user_id);
int sceSystemServiceGetAppIdOfRunningBigApp(void);
int sceSystemServiceKillApp(int app_id, int how, int reason, int core_dump);
int sceKernelGetAppState(int app_id, int*, int*);
```
Все есть в нашем SDK (libSceSystemService.so: sceSystemServiceLaunchApp ✓, libSceUserService.so ✓).

## 12. ПЛАН РЕАЛИЗАЦИИ (E3b) для pxlview

### Шаг 1: портировать pt_* helpers (ptrace) в pxlview
- из websrv pt.c: pt_attach, pt_follow_fork, pt_follow_exec, pt_continue, pt_await_child, pt_await_exec, pt_detach, pt_mmap, pt_copyin/out, pt_setlong, pt_syscall, pt_getregs/setregs
- либо сырые syscalls: PTRACE (0x0f?) с флагами PT_FOLLOW_FORK/PT_FOLLOW_EXEC

### Шаг 2: one-time setup FAKE00000
- remount /system_ex, создать каталог, param.json (attribute3=4), eboot.bin из NPXS40106
- проверить: /system_ex/app/NPXS40106 существует на 11.60?

### Шаг 3: launcher в pxlview (новый режим)
- find_pid("SceSysCore.elf")
- ptrace-hijack fork + sceSystemServiceLaunchApp("FAKE00000")
- int3 на main, загрузить pxlview-ELF (или продолжить выполнение кода pxlview в этом процессе)
- привилегии (uid=0, caps, rootdir, jaildir)

### Шаг 4: проверка дисплея
- в запущенном FAKE-процессе: VideoOut open + register + flip
- attribute3=4 → система должна маршрутизировать наш вывод на HDMI

### Риски
- /system_ex remount на 11.60 может отличаться (exfatfs?)
- sceSystemServiceLaunchApp может требовать дополнительные условия (HDCP, user session)
- KillApp текущего bigapp (VSH?) — осторожно
- Версия SDK: offact говорил про фикс запуска на 11.x в SDK 0.40 — наш SDK проверить/обновить

## 13. Результаты LAUNCH PROBE на железе (11.60)

| Проверка | Результат |
|---|---|
| /system_ex/app/NPXS40106/eboot.bin | ✅ существует, 4116882 байта (PS Now) |
| /system/vsh/app/NPXS40112/eboot.bin | ✅ существует, 252650 байт (ZeroConf) |
| /system_ex/app/FAKE00000 | ❌ нет (создаётся hbldr'ом) |
| sceUserServiceGetForegroundUser | ✅ rc=0, uid=0x1ea2f4d9 |
| sceSystemServiceGetAppIdOfRunningBigApp | 0xffffffff (нет запущенного bigapp) |
| nmount MNT_UPDATE /system_ex (все варианты опций) | ❌ EINVAL (8 комбинаций) |
| fresh mount /dev/ssd0.system_ex → /tmp/pxl_ex | ❌ EINVAL |
| /dev/ssd0.system_ex | ✅ существует |
| /dev_hdd0, /dev_hdd0/app, /dev_hdd0/data | ❌ **No such file or directory** |
| getmntinfo | 1056 маунтов, но **только 6 не-sandbox**: /system_tmp, /system, /system_ex, /system_data, /devlog/system, /system_data/eap/rodata |

### ⭐⭐⭐ Ключевой вывод: MOUNT WORLD

Наш процесс (WebKit payload) находится в **отдельном mount world**:
- Видит: только system-партиции (ro) + sandbox nullfs (1000+)
- НЕ видит: /dev_hdd0 (user-хранилище!), /mnt/nor0
- MNT_UPDATE/fresh mount на /system_ex → EINVAL (чужой mount world)

Следствия:
1. **FAKE00000 на /system_ex создать обычным способом нельзя** (нет записи)
2. **/dev_hdd0 (куда ставятся homebrew PKG) невидим**
3. Писать в /system_ex можно только через kernel- vnode-путь (как main payload) или через VSH-процесс

### ⭐ Вариант E (обходной, без записи в /system_ex):

**Запустить СУЩЕСТВУЮЩЕЕ системное приложение через sceSystemServiceLaunchApp и перехватить его:**
- `sceSystemServiceLaunchApp("NPXS40112")` — ZeroConf (тот же eboot, что у нас)
- или `sceSystemServiceLaunchApp("NPXS40106")` — PS Now (донор eboot у hbldr)
- ptrace-hijack (fork/exec на SceSysCore), int3 на main, загрузка pxlview-ELF
- param.json реального приложения уже имеет attribute3 (видео) → система настроит video-out
- **Ни одной записи в /system_ex!**

### Следующие шаги
1. **E5-эксперимент**: `sceSystemServiceLaunchApp("NPXS40112")` из diag + ptrace attach к дочернему + наблюдение (появится ли UI ZeroConf на мониторе)
2. Если да — полный hijack + pxlview в этом процессе + VideoOut flip
3. Альтернатива: kernel-vnode запись FAKE00000 в /system_ex (сложнее, но автономнее)

### Вопросы для интернета (новые)
- PS5 mount worlds / WebKit sandbox mount namespace — подтверждение, как переключиться (mount_world syscall номер на PS5)
- `sceSystemServiceLaunchApp` из payload — примеры вызова, блокирование, требования
- NPXS40112 ZeroConf — что показывает (UI?), есть ли у него attribute3=4 в param.json
- Можно ли запустить NPXS40106/NPXS40112 без user-login / когда VSH в меню

## 14. Реальные приложения на консоли (/system_ex/app, 11.60)

| App | attr3 | category |
|---|---|---|
| NPXS40000 | — | 33554432 (Daemon) |
| NPXS40028 | — | 33554432 (Daemon) |
| **NPXS40074** | **4** (video-out) | ? |
| NPXS40087 | 1024 | ? |
| **NPXS40099** | **4** (video-out) | ? |
| NPXS40106 (PS Now) | **0** (!!) | ? |
| **NPXS40140 (Disc Player 2)** | **4** (video-out) | ? |
| NPXS40146 | 0 | ? |
| NPXS40204 | — | 33554432 (Daemon) |
| NPXS40210 | 0 | ? |
| NPXS40250 | 1840128 | ? |
| NPXS40255 | 0 | ? |

### ⭐ Ключевые выводы
1. **NPXS40106 (PS Now) имеет attr3=0** — донор eboot'а FAKE00000 сам НЕ видео-приложение.
   → **video-out определяется param.json приложения, а НЕ eboot'ом.** eboot — просто «валидный» бинарник.
2. **Есть реальные видео-аппы с attr3=4**: NPXS40074, NPXS40099, NPXS40140 (Disc Player 2)
3. ZeroConf (40112) — резидентный VSH-демон (SLEEP, ppid=50, из shsrv ps-выписки), не foreground-апп

### Эксперимент E5 (следующий)
` sceSystemServiceLaunchApp("NPXS40140")` (Disc Player 2) из diag:
1. Запустить через систему (в потоке, blocking)
2. Наблюдать за монитором: появится ли UI Disc Player (доказательство display handoff)
3. Если да — ptrace-hijack процесса + загрузка pxlview + VideoOut flip
4. Альтернативные кандидаты: NPXS40074, NPXS40099



## 15. ⭐⭐⭐ E6: APP HIJACK — ПРОБИТИЕ ДИСПЛЕЯ (11.60)

### Что сделано
1. Порт `pt.c` (ptrace-хелперы из websrv/hbldr) + `elfldr_hw.c` (ELF-загрузчик в процесс) в pxlview
2. Ключевые находки по пути:
   - ptrace требует authid `0x4800000000010003` + полные caps (save/restore вокруг вызова)
   - `pt_mmap` с `MAP_ANON=0x1000` (НЕ 0x100!) — иначе PT_IO-запись в страницу падает EINVAL
   - PT_IO запись в mmap-страницу и стек цели работает; kernel_proc_copyin — EPERM
   - `pt_attach(1)` (init) — ECHILD (нельзя трассировать)
   - Remote-syscall в контексте SceSysCore (pid 53): mmap OK, но statfs/open/nmount — все EPERM
     (трассируемый тред не имеет прав на VFS-операции?)
   - `LaunchApp` из нашего контекста: rc=24/24600 (EROFS) НО **приложение запускается!**
3. **E6-алгоритм** (как у hbldr):
   - kqueue EVFILT_PROC (FORK|EXEC|TRACK) на SceSysCore (pid 53)
   - поток: `sceSystemServiceLaunchApp("NPXS40140")`
   - kevent → fork child (pid 676)
   - pt_attach → pt_follow_exec → pt_continue → pt_await_exec
   - pt_syscall(599) — dynlib relocation; set_heap_size; raise_privileges
   - int3 на `kernel_dynlib_entry_addr(child, 0) + 58` (вызов main eboot)
   - `elfldr_exec(child, pxlview_elf)` — загрузка pxlview (stripped, embedded blob)

### ⭐ РЕЗУЛЬТАТ НА ЖЕЛЕЗЕ
- **fork child: 676 → exec'd → stopped at brk 0x42c100aa → pxlview loaded — GO!**
- **На мониторе: СИНИЙ ЭКРАН** (время жизни pxlview), после выхода payload — ЧЁРНЫЙ ЭКРАН
- **Консоль НЕ зависла**: интерфейс VSH работает (кнопка PS на геймпаде открывает меню)
- pxlview-логи НЕ дошли до консоли (stdio приложения — не наш TCP)

### Выводы
1. **Формальный запуск приложения = дисплей наш.** pxlview в контексте запущенного
   приложения видит дисплей (синий экран = вероятно, UI pxlview с тёмно-синим фоном)
2. EROFS в LaunchApp — не фатален: приложение всё равно запускается
3. После смерти приложения дисплей остаётся чёрным (VSH жив, но не обновляет кадр —
   как при kill-78; восстановление — переподключение HDMI)

### Следующие шаги
1. Уточнить: синий экран — однотонный или с текстом/панелями pxlview?
2. Вернуть дисплей (HDMI re-plug)
3. stdio pxlview → наш TCP (elfldr_set_stdio с нашим fd) для логов
4. Чистый handoff дисплея назад в VSH при выходе pxlview (чтобы не чёрный экран)
5. Input (DualSense) в контексте приложения
6. Коммит состояния dev-apps

## 16. ⭐⭐⭐⭐ E6.1: pxlview UI В КОНТЕКСТЕ ПРИЛОЖЕНИЯ (11.60)

### Фиксы, приведшие к успеху
1. **SDL: display 0 с fallback на 2** (`PS5_VideoOutOpenAny`):
   - в контексте запущенного приложения display 0 = дисплей приложения
   - `(0xff, 2, 0)` в app-контексте давал EAGAIN ("вторичный" дисплей недоступен)
   - патч SDL2 регенерирован (110 строк), base = ee4c47d
2. **close_eboot_vout_sessions()** в console_ui.c: eboot приложения открывает
   VideoOut-сессию до main(); close(fd) по ней — rc=-1 (EBUSY), но с display 0
   это уже не критично
3. **KillApp перед запуском** (running bigapp → sceSystemServiceKillApp) —
   иначе LaunchApp не форкает новый процесс (LNC "already running")
4. **stdio pxlview → наш TCP** (elfldr_set_stdio) — логи видны!
5. **kevent timeout 30s** — без него diag зависал при "already running"

### ⭐ РЕЗУЛЬТАТ
```
[pxlview] starting v0.1.0
[pxlview] kernel access ok
[pxlview] collected 3824 bytes of panel text (procs=48 nor=1 hv=0)
[pxlview-ui] window 1920x1080 fmt=0x16762004
[pxlview-ui] joystick 0: User1
[diag]   t+1..t+20: pid 691 alive state=0x0 comm=SceDiscPlayer
```
- **ОКНО СОЗДАНО** (display 0), **ГЕЙМПАД ОТКРЫТ** (User1 = DualSense!)
- pxlview живёт 20+ секунд в процессе приложения
- notify pxlview работает (виден Debug-панель VSH: "pxlview v0.1.0: display FAILED"
  в проваленном ране)
- Чистый выход приложения → **меню VSH восстанавливается САМО** (без re-plug HDMI)

### Следующие шаги
1. Убрать E5/LAUNCH TEST после E6 (не переключать дисплей) — чистый ран pxlview
2. Удлиннить жизнь pxlview (сейчас diag убивает payload через ~30с)
3. Проверить, что видно на экране (UI pxlview с панелями?)
4. Input: DualSense уже открыт — проверить навигацию панелей
5. Перенести hijack-механизм из diag в основную жизнь pxlview
   (самозапуск: payload сам запускает апп, хиджакит себя)
