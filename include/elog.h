#ifndef ELOG_H
#define ELOG_H

/* Run log: tees every log line to the serial console AND to a uniquely
 * named file on the external SSD (first available USB storage), falling
 * back to the payload data area /data when no USB is mounted.
 *
 * File naming:  byepv<fw>_<YYYYMMDD>_<HHMMSS>.log   (wall clock)
 *               byepv<fw>_run<N>.log                (clock unsynced)
 *
 * The file is opened unbuffered at init and stays open across the rest
 * mode cycle, so a single run (arm -> sleep -> resume -> proof) is one
 * file. If the console dies mid-run, everything written so far survives.
 */

void elog_init(void);
void elog(const char *fmt, ...);
void elog_notify(const char *fmt, ...);
void elog_finish(void);

#endif // ELOG_H
