#ifndef H1160_H
#define H1160_H

/* Hardened 11.60 resume hook: 16 isolated per-core IST6 entry paths around
 * the global #DB (vector 1) gate.
 *
 * Design (validated against the 11.60 production port, see
 * tools/ps5-hv-bypass-porting/docs/multicore-debug-hook.md):
 *
 *   - The vector 1 gate is global, so every CPU needs a safe entry path.
 *   - TSS row 0 (the selected CPU) gets the real arm/handler chain.
 *   - TSS rows 1..15 get a register-neutral passthrough: pop rsp; iretq.
 *   - The stock gate is restored as the FIRST handler mutation, DR7 is
 *     cleared before the AP payload is staged, and the global gate is
 *     published as the LAST installation write.
 *   - All 16 original IST6 values are saved and restored independently,
 *     each with a readback.
 *
 * Cave layout (relative to the data cave base). Geometry is shared with the
 * validated 11.60 production port so the AP payload parameter/result
 * contract stays identical:
 *
 *   0x0440  oracle block (8 qwords, shared with khook KH_OFF_USER)
 *   0x0600  state word (H1160_STATE_ARMED)
 *   0x0680  preparation mark (H1160_PREP_MARK, written before rest)
 *   0x1000  arm block (0x400: ROP @0x50, ctx @0x100, cont @0x200)
 *   0x1400  passthrough stacks, 15 x 0x100 (CPUs 1..15)
 *   0x2400  production handler (0x400: ROP @0x50, iret tramp @0x20,
 *           5-qword privilege frame @0x28..0x50)
 *   0x2800  AP payload staging source (0x800)
 *   0x3000  recovery save area: state @+0x00, gate_lo @+0x08,
 *           gate_hi @+0x10, ist[16] @+0x18
 *   0x3400  AP result stash (10 qwords, filled by the AP payload)
 */

#include <stddef.h>
#include <stdint.h>

#define H1160_NCPU           16
#define H1160_TSS_STRIDE     0x68ULL

#define H1160_ORACLE_OFF     0x440ULL
#define H1160_STATE_OFF      0x600ULL
#define H1160_PREP_OFF       0x680ULL
#define H1160_ARM_OFF        0x1000ULL
#define H1160_FALL_OFF       0x1400ULL
#define H1160_HANDLER_OFF    0x2400ULL
#define H1160_STAGE_OFF      0x2800ULL
#define H1160_SAVE_OFF       0x3000ULL
#define H1160_STASH_OFF      0x3400ULL

#define H1160_BLOCK          0x400ULL   // arm / handler block size
#define H1160_FALL_SIZE      0x100ULL   // one passthrough stack
#define H1160_STAGE_SIZE     0x800ULL   // AP payload staging area

/* Per-stack internal geometry (within a 0x100 or 0x400 block):
 * ROP chain starts at 0x50 (grows up), IRETQ trampoline qword at 0x20,
 * the 5-qword hardware privilege frame at 0x28..0x50. */
#define H1160_TOP            0x50ULL
#define H1160_IRET_OFF       0x20ULL
#define H1160_FRAME_OFF      0x28ULL

#define H1160_STATE_ARMED    0x493950524F444152ULL /* "I9PRODAR" */
#define H1160_PREP_MARK      0x315045525054584BULL /* "KXTPREP1" */
#define H1160_CHAIN_MARK     0x434841494E2D3031ULL /* "CHAIN-01" */

/* AP payload mode tag and result markers (contract with break_hv.c). */
#define H1160_AP_MODE        0x313631312D504142ULL /* "BAP-1161" */
#define H1160_MARK_ENTERED   0x454E544552454431ULL /* "ENTERED1" */
#define H1160_MARK_DONE      0x444F4E452D415031ULL /* "DONE-AP1" */
#define H1160_MODE_STRIKE    0x31454B4952545356ULL /* "VSTRIKE1" */

#define H1160_PAYLOAD_PAGE   0x3FFFF000ULL

int  h1160_is_armed(uint64_t cave);
int  h1160_arm(uint64_t cave, uint64_t cr3, uint64_t hv_loader_pa,
               const uint8_t *payload, size_t payload_len);
int  h1160_cleanup(uint64_t cave);

/* Result helpers used by the outer payload after rest/resume. */
int  h1160_result_done(uint64_t cave);
int  h1160_result_success(uint64_t cave);
void h1160_result_print(uint64_t cave);

/* Pre-arm read-only forensics: gate, IST6 slots, and cave residue. */
void h1160_forensics(uint64_t cave);

#endif // H1160_H
