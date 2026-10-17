/*
 * elog.c - run log: serial + file on external SSD.
 *
 * Build variants (see Makefile VARIANT):
 *   debug      - file log on USB + live stdout stream (default);
 *   release    - no USB file (PXEL_NO_USB), live stdout stream;
 *   standalone - no USB file, stdout is non-blocking (PXEL_STANDALONE):
 *                the payload must never block on a missing host listener,
 *                verdicts reach the user via on-screen notifications.
 *
 * Storage policy (debug only, first that accepts a new file):
 *   1. USB storage: /host/USB000..USB007, then /mnt/usb0..usb7
 *      (both mount families appear across PS5 firmware generations)
 *   2. /data - the payload data area (always present)
 *   3. serial only (degraded; a notification says so)
 *
 * The log is the primary artifact for the test report
 * (see analysis/TEST_11_60_PROCEDURE.md section 8).
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

#include <ps5/kernel.h>

#include "elog.h"
#include "util.h"
#include "version.h"

static FILE *s_log = NULL;
static char s_path[256] = "";
static time_t s_start = 0;

/* First directory that exists and is accessible. */
static int find_storage_dir(char *dir, size_t dir_len)
{
  static const char *usb_dirs[] = {
    "/host/USB000", "/host/USB001", "/host/USB002", "/host/USB003",
    "/host/USB004", "/host/USB005", "/host/USB006", "/host/USB007",
    "/mnt/usb0", "/mnt/usb1", "/mnt/usb2", "/mnt/usb3",
    "/mnt/usb4", "/mnt/usb5", "/mnt/usb6", "/mnt/usb7",
  };

  for (size_t i = 0; i < sizeof usb_dirs / sizeof usb_dirs[0]; i++) {
    if (access(usb_dirs[i], R_OK | X_OK) == 0) {
      snprintf(dir, dir_len, "%s", usb_dirs[i]);
      return 0;
    }
  }
  if (access("/data", R_OK | X_OK) == 0) {
    snprintf(dir, dir_len, "/data");
    return 0;
  }
  return -1;
}

/* Unique run counter, persisted in the storage dir (clock-unsynced case). */
static int next_run_counter(const char *dir)
{
  char count_path[288];
  FILE *cf;
  int n = 0;

  snprintf(count_path, sizeof count_path, "%s/byepv_run_count", dir);
  cf = fopen(count_path, "r");
  if (cf) {
    if (fscanf(cf, "%d", &n) != 1)
      n = 0;
    fclose(cf);
  }
  n++;
  cf = fopen(count_path, "w");
  if (cf) {
    fprintf(cf, "%d", n);
    fclose(cf);
  }
  return n;
}

static int next_run_counter(const char *dir);
static void elog_dump_previous_log(const char *dir);

void elog_init(void)
{
  time_t now = 0;
  uint32_t fw = (uint32_t)kernel_get_fw_version();

  /* The stdout pipe is the elfldr TCP socket: unbuffer it so every line
   * reaches the host listener in real time (file below is unbuffered too).
   * Standalone: additionally non-blocking, so a missing host listener can
   * never wedge the payload (lines are dropped, process keeps running). */
  setvbuf(stdout, NULL, _IONBF, 0);
#ifdef PXEL_STANDALONE
  {
    int fl = fcntl(STDOUT_FILENO, F_GETFL, 0);
    if (fl >= 0)
      fcntl(STDOUT_FILENO, F_SETFL, fl | O_NONBLOCK);
  }
#endif

  time(&now);

#ifdef PXEL_NO_USB
  (void)fw;
  printf("[elog] %s build: no USB log file, stdout stream only\n",
         PXEL_VARIANT);
  return;
#else
  char dir[256];
  struct tm tmv = {};

  if (find_storage_dir(dir, sizeof dir) != 0) {
    printf("[elog] no storage available (USB//data), serial-only log\n");
    notifyf("Byepervisor Reborn\nLog: no USB storage, serial only");
    return;
  }

  if (now > 0x50000000) {   /* ~2010: sane wall clock */
    localtime_r(&now, &tmv);
    snprintf(s_path, sizeof s_path,
             "%s/byepv%u%u_%04d%02d%02d_%02d%02d%02d.log",
             dir, (fw >> 16) & 0xff, (fw >> 8) & 0xff,
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
  } else {
    int n = next_run_counter(dir);
    snprintf(s_path, sizeof s_path,
             "%s/byepv%u%u_run%d.log", dir, (fw >> 16) & 0xff, (fw >> 8) & 0xff, n);
  }

  s_log = fopen(s_path, "w");
  if (!s_log) {
    printf("[elog] cannot open %s, serial-only log\n", s_path);
    notifyf("Byepervisor Reborn\nLog: open failed, serial only");
    s_path[0] = 0;
    return;
  }
  setvbuf(s_log, NULL, _IONBF, 0);   /* every line hits the SSD immediately */

  s_start = now;
  fprintf(s_log, "========================================\n");
  fprintf(s_log, "Byepervisor-Reborn run log\n");
  fprintf(s_log, "build: %s %s\n", __DATE__, __TIME__);
  fprintf(s_log, "firmware: %u.%u  (raw 0x%x)\n",
          (fw >> 24) & 0xff, (fw >> 16) & 0xff, fw);
  fprintf(s_log, "soc: 0x%x\n", sceKernelGetMainSocId());
  fprintf(s_log, "path: %s\n", s_path);
  fprintf(s_log, "started: %ld (%s)\n", (long)now,
          now > 0x50000000 ? "wall clock" : "clock unsynced");
  fprintf(s_log, "========================================\n");

  printf("[elog] run log: %s\n", s_path);

  /* Stream the most recent previous run log (by mtime) to stdout: the
   * file persists across reboots, so the host capture of this run also
   * carries the console-side log of the previous (possibly crashed) run. */
  elog_dump_previous_log(dir);
#endif
}

static void elog_dump_previous_log(const char *dir)
{
  DIR *d;
  struct dirent *de;
  char best[256] = "";
  time_t best_mt = 0;

  d = opendir(dir);
  if (!d)
    return;
  while ((de = readdir(d))) {
    char path[512];
    struct stat st;
    const char *n = de->d_name;
    size_t nl = strlen(n);

    if (nl < 10 || strncmp(n, "byepv", 5) != 0 ||
        strcmp(n + nl - 4, ".log") != 0)
      continue;
    snprintf(path, sizeof path, "%s/%s", dir, n);
    if (strcmp(path, s_path) == 0)
      continue;               /* current run */
    if (stat(path, &st) != 0)
      continue;
    if (st.st_mtime > best_mt) {
      best_mt = st.st_mtime;
      snprintf(best, sizeof best, "%s", path);
    }
  }
  closedir(d);
  if (!best[0])
    return;

  {
    FILE *pf = fopen(best, "r");
    if (!pf)
      return;
    elog("[elog] previous run log: %s\n", best);
    {
      int c;
      size_t lines = 0;
      while ((c = fgetc(pf)) != EOF && lines < 4000) {
        putchar(c);
        if (c == '\n')
          lines++;
      }
    }
    fclose(pf);
    elog("[elog] previous run log end\n");
  }
}

void elog(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vprintf(fmt, ap);   /* standalone: non-blocking, EAGAIN drops the line */
  va_end(ap);

  if (s_log) {
    va_start(ap, fmt);
    vfprintf(s_log, fmt, ap);
    va_end(ap);
  }
}

void elog_notify(const char *fmt, ...)
{
  char msg[512];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(msg, sizeof msg, fmt, ap);
  va_end(ap);

  notifyf("%s", msg);
  elog("[NOTIFY] %s", msg);
}

void elog_finish(void)
{
  if (s_log) {
    time_t now = 0;
    time(&now);
    fprintf(s_log, "========================================\n");
    fprintf(s_log, "end: %ld  elapsed: %ld s\n", (long)now,
            (long)(now - s_start));
    fprintf(s_log, "========================================\n");
    fclose(s_log);
    s_log = NULL;
    elog("elog: log file closed (%s)\n", s_path);
  } else {
    /* No file (serial-only run, or a no-USB build): emit the same terminal
     * marker on stdout so host tooling (scripts/ps5_run.py) can distinguish
     * a clean payload exit from a dropped connection. */
    elog("elog: log file closed (no file, %s build)\n", PXEL_VARIANT);
  }
}
