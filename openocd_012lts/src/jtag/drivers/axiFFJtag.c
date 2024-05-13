/* SPDX-License-Identifier: GPL-2.0
 *
 *	 Copyright (C) 2019 Google, LLC.
 *	 Moritz Fischer <moritzf@google.com>
 *
 *	 Copyright (C) 2021 Western Digital Corporation or its affiliates
 *	 Jeremy Garff <jeremy.garff@wdc.com>
 */

/*
 * This implementation was derived from the PCIe Xilinx Debug Bridge driver
 * found in xlnx-pcie-xvc.c.  Instead of using PCIe, this driver is used
 * for direct AXI connections.	This is useful where OpenOCD is running in
 * a Zynq or on a MicroBlaze with direct access to the register interface.
 * of the debug bridge.
 *
 * Future enhancements should include combining this with the PCIe driver
 * to optimize use of common code and reduce duplication.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <helper/bits.h>
#include <helper/replacements.h>
// #include <jtag/commands.h>
#include <jtag/interface.h>
#include <jtag/swd.h>
#include <linux/pci.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

/* system includes */
#include <fcntl.h>
#include <gpiod.h>
#include <inttypes.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define XLNX_XVC_LEN_REG 0x00
#define XLNX_XVC_TMS_REG 0x04
#define XLNX_XVC_TDI_REG 0x08
#define XLNX_XVC_TDO_REG 0x0c
#define XLNX_XVC_CTRL_REG 0x10
#define XLNX_XVC_DIV_REG \
  0x14 /* Non-standard register added to Xilinx HDL -- JG */
#define XLNX_XVC_MAX_REG 0x18

#define XLNX_XVC_CTRL_REG_ENABLE_MASK 0x01

#define XLNX_XVC_BASE_FREQ 100000000 /* 100Mhz */

#define XLNX_XVC_MAX_BITS 0x20

#define MASK_ACK_axiffjtag(x) (((x) >> 1) & 0x7)
#define MASK_PAR(x) ((int)((x) & 0x1))

struct xlnx_axi_signal {
  char *name;
  struct gpiod_line *line;
};

#define AFF_PKG_32SIZE \
  8192  // 以前是1024，在运行svf的时候出现溢出错误，所以改成4096
#define AFF_PKG_8SIZE (AFF_PKG_32SIZE * 4)
union u4B2B {
  uint32_t u32;
  uint8_t u8[4];
};
typedef struct {
  union u4B2B len[AFF_PKG_32SIZE];
  union u4B2B tms[AFF_PKG_32SIZE];
  union u4B2B tdi[AFF_PKG_32SIZE];
  union u4B2B wcb[AFF_PKG_32SIZE];
  union u4B2B tdo[AFF_PKG_32SIZE];
  int32_t bytesLeft;
  int32_t needBereadBytes;
} affJtag_pkg;

typedef struct {
  uint32_t jtag_clk_offset;  // reg0 jtag clk = 25000/n
  uint32_t enable_offset;    // reg1 nc
  uint32_t lenght_offset;    // reg2
  uint32_t tms_offset;       // reg3
  uint32_t tdi_offset;       // reg4
  uint32_t wrback_offset;    // reg5 //0x55aa0000, readback
  uint32_t full_offset;   // reg6 [3:0] [11:8]=len,tms,tdi,wb fifo empty signal;
  uint32_t empty_offset;  // reg7 [0]
  uint32_t tdo_offset;    // reg8
  uint32_t reset_offset;  // reg9 //0x0000aaaa reset jtag, 0x0000 do nothing
                          // except clear enable, reset
} affJtag_t;

struct xlnx_axiffjtag_xvc {
  int fd;
  uint32_t *baseaddr;
  volatile affJtag_t *ptr;
  char *deviceaddr;
  struct xlnx_axi_signal trst;
  struct xlnx_axi_signal srst;
};

#define CLK_T 40  // 40ns
#define RESET_CMD_CLK (0x0000aaaa)
#define RESET_CMD_JTAG (0x0000aaa5)
#define REQUEST_WCB (0x55aa0000)
#define REAL_SEND (0x00000001)
#define NOT_REAL_SEND (0x00000000)

static void reset_affjtag(volatile affJtag_t *ptr, int32_t N_ns) {
  // 25Mhz 40ns,
  N_ns = N_ns;
  uint32_t clk = N_ns / CLK_T;
  clk = clk;
  LOG_DEBUG_IO("affjtag ptr addr(0x%08x)", (uint32_t)ptr);
  // ptr->jtag_clk_offset = 1000;
  ptr->jtag_clk_offset = clk;
  ptr->reset_offset = RESET_CMD_CLK;
  usleep(10);
  ptr->reset_offset = 0x0000;
  usleep(10);
  LOG_DEBUG_IO("affjtag ptr->clk_offset val(0x%08x)",
               (uint32_t)ptr->jtag_clk_offset);
}

static void set_affjtag_clk(volatile affJtag_t *ptr, int32_t N_ns) {
  N_ns = N_ns;
  uint32_t clk = N_ns / CLK_T;
  clk = clk;
  LOG_DEBUG_IO("affjtag ptr addr(0x%08x)", (uint32_t)ptr);
  // ptr->jtag_clk_offset = 1000;
  ptr->jtag_clk_offset = clk;
}
static void reset_only_affjtag(volatile affJtag_t *ptr) {
  ptr->reset_offset = RESET_CMD_JTAG;
  usleep(10);
  ptr->reset_offset = 0x0000;
  usleep(10);
}

static struct xlnx_axiffjtag_xvc axi_ffjtag_state;
static struct xlnx_axiffjtag_xvc *xlnx_axiffjtag_xvc = &axi_ffjtag_state;

affJtag_pkg affJtagPkg;

static void axi_ffjtag_clear_pkg(affJtag_pkg *affjpkg) {
  do {
    int32_t clen = 0;
    if (affjpkg->bytesLeft == 0) {
      clen = AFF_PKG_8SIZE;
    } else {
      clen = affjpkg->bytesLeft;
    }
    memset(affjpkg->len[0].u8, 0, clen);
    memset(affjpkg->tms[0].u8, 0, clen);
    memset(affjpkg->tdi[0].u8, 0, clen);
    memset(affjpkg->wcb[0].u8, 0, clen);
    memset(affjpkg->tdo[0].u8, 0, clen);
    affjpkg->needBereadBytes = 0;
    affjpkg->bytesLeft = 0;
  } while (0);
}

static void axi_ffjtag_opr_queue(affJtag_pkg *affjpkg) {
  volatile affJtag_t *ptr = xlnx_axiffjtag_xvc->ptr;
  uint32_t tmp_tdo;
  int alread_RBn = 0;
  int alread_SBn = 0;
  uint32_t stms = 0, stdi = 0, slen = 0, scb = 0;
  // uint8_t *result = affjpkg->tdo[0].u8;
  int32_t bytesLeft = affjpkg->bytesLeft;
  int32_t i = 0;
  int32_t needBereadBytes = affjpkg->needBereadBytes;

  while (1) {                               // main loop
    if ((ptr->empty_offset & 0x01) != 1) {  // rec fifo is not empty
      while (1) {                           // rec all data
        if ((ptr->empty_offset & 0x01) == 1) {
          break;
        } else {
          tmp_tdo = ptr->tdo_offset;
          affjpkg->tdo[alread_RBn / 4].u32 = tmp_tdo;
          alread_RBn = alread_RBn + 4;
        }
        // LOG_DEBUG_IO("in ptr->empty_offset & 0x01) != 1");
      }

    }  //// send queue// sff_status

    else if (((ptr->full_offset & 0x0f) == 0x00) && (alread_SBn <= bytesLeft)) {
      while (1) {  // until ptr->full_offset & 0x0f == 0xf

        if (((ptr->full_offset & 0x0f) != 0x00) || (alread_SBn >= bytesLeft)) {
          break;
        } else {
          scb = affjpkg->wcb[alread_SBn / 4].u32;
          slen = affjpkg->len[alread_SBn / 4].u32;
          stms = affjpkg->tms[alread_SBn / 4].u32;
          stdi = affjpkg->tdi[alread_SBn / 4].u32;
          // LOG_DEBUG_IO(
          //     "in while(1) affjtag write last "
          //     "slen(%d),stms(%d),stdi(%d),scb(%d)",
          //     slen, stms, stdi, scb);
          // LOG_DEBUG_IO("alread_SBn / 4 = 0X%08X", (alread_SBn / 4));
          ptr->lenght_offset = slen;
          ptr->tms_offset = stms;
          ptr->tdi_offset = stdi;
          ptr->wrback_offset = scb;

          alread_SBn += 4;
        }
      }
    }
    // LOG_DEBUG_IO("in main while(1) alread_RBn(%d)-needBereadBytes(%d),
    // alread_SBn(%d)-bytesLeft(%d)",
    //              alread_RBn, needBereadBytes,alread_SBn, bytesLeft);

    if ((alread_RBn >= needBereadBytes) && (alread_SBn >= bytesLeft) &&
        ((ptr->full_offset & 0x0f00) ==
         0x0f00)) {  // if rec num > bytesLeft ,return;
      LOG_DEBUG_IO("already send bytes(%d)  should be sent bytes(%d)",
                   alread_SBn, bytesLeft);
      LOG_DEBUG_IO("already rec  bytes(%d)  should be rec bytes(%d)",
                   alread_RBn, needBereadBytes);
      for (i = 0; i < needBereadBytes / 4; i++) {
        LOG_DEBUG_IO("tdo:(%i)[0x%08x] ", i, affjpkg->tdo[i].u32);
      }
      for (i = 0; i < bytesLeft / 4; i++) {
        LOG_DEBUG_IO("(%i):tdi[0x%08x]tms[0x%08x]len[0x%08x]wcb[0x%08x] ", i,
                     affjpkg->tdi[i].u32, affjpkg->tms[i].u32,
                     affjpkg->len[i].u32, affjpkg->wcb[i].u32);
      }
      i = i;
      break;  // break; main while(1)
    }
  }
}

static int32_t pkgI = 0;
static int axi_ffjtag_transact(size_t num_bits, uint32_t tms, uint32_t tdi,
                               uint32_t *tdo, uint32_t realDo) {
  // int32_t i=0;
  // affJtag_pkg *affjpkg = &affJtagPkg;
  if (num_bits != 0) {
    affJtagPkg.len[pkgI].u32 = num_bits;
    affJtagPkg.tms[pkgI].u32 = tms;
    affJtagPkg.tdi[pkgI].u32 = tdi;
    affJtagPkg.bytesLeft += 4;

    if (tdo != NULL) {
      affJtagPkg.wcb[pkgI].u32 = REQUEST_WCB;
      affJtagPkg.needBereadBytes += 4;
    } else {
      affJtagPkg.wcb[pkgI].u32 = 0;
    }
    pkgI++;
    if (pkgI >= AFF_PKG_32SIZE) {
      LOG_ERROR("affJtag buf overflow**********pkgI=%d,while(1) stop", pkgI);
      while (1) {
        usleep(1000);
      }
    }
  }

  if (realDo == REAL_SEND) {
    axi_ffjtag_opr_queue(&affJtagPkg);  // real send and rec
    // axi_ffjtag_clear_pkg(&affJtagPkg);
    pkgI = 0;
  }

  return ERROR_OK;
}

static int axi_ffjtag_execute_stableclocks(struct jtag_command *cmd) {
  int tms = tap_get_state() == TAP_RESET ? 1 : 0;
  size_t left = cmd->cmd.stableclocks->num_cycles;
  size_t write;
  int err;

  LOG_DEBUG_IO("stableclocks %i cycles", cmd->cmd.runtest->num_cycles);

  while (left) {
    write = MIN(XLNX_XVC_MAX_BITS, left);
    err = axi_ffjtag_transact(write, tms, 0, NULL, NOT_REAL_SEND);
    if (err != ERROR_OK) return err;
    left -= write;
  };
  axi_ffjtag_transact(0, 0, 0, NULL, REAL_SEND);  // cahilladd
  axi_ffjtag_clear_pkg(&affJtagPkg);
  return ERROR_OK;
}

static int axi_ffjtag_execute_statemove(size_t skip) {
  uint8_t tms_scan = tap_get_tms_path(tap_get_state(), tap_get_end_state());
  int tms_count = tap_get_tms_path_len(tap_get_state(), tap_get_end_state());
  int err;

  LOG_DEBUG_IO("statemove starting at (skip: %zu) %s end in %s", skip,
               tap_state_name(tap_get_state()),
               tap_state_name(tap_get_end_state()));

  err = axi_ffjtag_transact(tms_count - skip, tms_scan >> skip, 0, NULL,
                            REAL_SEND);
  // axi_ffjtag_transact(0, 0, 0, NULL, REAL_SEND);  // cahill add
  axi_ffjtag_clear_pkg(&affJtagPkg);
  if (err != ERROR_OK) return err;

  tap_set_state(tap_get_end_state());

  return ERROR_OK;
}

static int axi_ffjtag_execute_runtest(struct jtag_command *cmd) {
  int err = ERROR_OK;

  LOG_DEBUG_IO("runtest %i cycles, end in %i", cmd->cmd.runtest->num_cycles,
               cmd->cmd.runtest->end_state);

  tap_state_t tmp_state = tap_get_end_state();

  if (tap_get_state() != TAP_IDLE) {
    tap_set_end_state(TAP_IDLE);
    err = axi_ffjtag_execute_statemove(0);
    if (err != ERROR_OK) return err;
  };

  size_t left = cmd->cmd.runtest->num_cycles;
  size_t write;

  while (left) {
    write = MIN(XLNX_XVC_MAX_BITS, left);
    err = axi_ffjtag_transact(write, 0, 0, NULL, NOT_REAL_SEND);
    if (err != ERROR_OK) return err;
    left -= write;
  };
  axi_ffjtag_transact(0, 0, 0, NULL, REAL_SEND);  // cahill add
  axi_ffjtag_clear_pkg(&affJtagPkg);
  tap_set_end_state(tmp_state);
  if (tap_get_state() != tap_get_end_state())
    err = axi_ffjtag_execute_statemove(0);

  return err;
}

static int axi_ffjtag_execute_pathmove(struct jtag_command *cmd) {
  size_t num_states = cmd->cmd.pathmove->num_states;
  tap_state_t *path = cmd->cmd.pathmove->path;
  int err = ERROR_OK;
  size_t i;

  LOG_DEBUG_IO("pathmove: %i states, end in %i", cmd->cmd.pathmove->num_states,
               cmd->cmd.pathmove->path[cmd->cmd.pathmove->num_states - 1]);

  for (i = 0; i < num_states; i++) {
    if (path[i] == tap_state_transition(tap_get_state(), false)) {
      err = axi_ffjtag_transact(1, 1, 0, NULL, NOT_REAL_SEND);
    } else if (path[i] == tap_state_transition(tap_get_state(), true)) {
      err = axi_ffjtag_transact(1, 0, 0, NULL, NOT_REAL_SEND);
    } else {
      LOG_ERROR("BUG: %s -> %s isn't a valid TAP transition.",
                tap_state_name(tap_get_state()), tap_state_name(path[i]));
      err = ERROR_JTAG_QUEUE_FAILED;
    }
    if (err != ERROR_OK) return err;
    tap_set_state(path[i]);
  }
  axi_ffjtag_transact(0, 0, 0, NULL, REAL_SEND);  // cahill add
  axi_ffjtag_clear_pkg(&affJtagPkg);
  tap_set_end_state(tap_get_state());

  return ERROR_OK;
}

static int axi_ffjtag_execute_scan(struct jtag_command *cmd) {
  enum scan_type type = jtag_scan_type(cmd->cmd.scan);
  tap_state_t saved_end_state = cmd->cmd.scan->end_state;
  bool ir_scan = cmd->cmd.scan->ir_scan;
  uint32_t tdi, tms, tdo;
  uint8_t *buf, *rd_ptr, *crd_ptr;
  int err, scan_size;
  size_t write;
  size_t left;
  int i = 0, ii = 0;

  scan_size = jtag_build_buffer(cmd->cmd.scan, &buf);
  rd_ptr = buf;
  crd_ptr = buf;
  LOG_DEBUG_IO("%s scan type %d %d bits; starts in %s end in %s",
               (cmd->cmd.scan->ir_scan) ? "IR" : "DR", type, scan_size,
               tap_state_name(tap_get_state()),
               tap_state_name(cmd->cmd.scan->end_state));

  /* If we're in TAP_DR_SHIFT state but need to do a IR_SCAN or
   * vice-versa, do a statemove to corresponding other state, then restore
   * end state
   */
  if (ir_scan && tap_get_state() != TAP_IRSHIFT) {
    tap_set_end_state(TAP_IRSHIFT);
    err = axi_ffjtag_execute_statemove(0);
    if (err != ERROR_OK) goto out_err;
    tap_set_end_state(saved_end_state);
  } else if (!ir_scan && (tap_get_state() != TAP_DRSHIFT)) {
    tap_set_end_state(TAP_DRSHIFT);
    err = axi_ffjtag_execute_statemove(0);
    if (err != ERROR_OK) goto out_err;
    tap_set_end_state(saved_end_state);
  }
  left = scan_size;
  while (left) {
    write = MIN(XLNX_XVC_MAX_BITS, left);
    /* the last TMS should be a 1, to leave the state */
    tms = left <= XLNX_XVC_MAX_BITS ? BIT(write - 1) : 0;
    tdi = (type != SCAN_IN) ? buf_get_u32(rd_ptr, 0, write) : 0;
    err = axi_ffjtag_transact(write, tms, tdi, type != SCAN_OUT ? &tdo : NULL,
                              NOT_REAL_SEND);

    if (err != ERROR_OK) goto out_err;
    left -= write;

    // cahill delet
    // if (type != SCAN_OUT) buf_set_u32(rd_ptr, 0, write, tdo);
    // rd_ptr += sizeof(uint32_t);
    // if (type != SCAN_OUT) {
    //   ii++;
    // }
    ii++;
    rd_ptr += sizeof(uint32_t);
  };
  if (scan_size) {
    axi_ffjtag_transact(0, 0, 0, NULL, REAL_SEND);  // cahill add
    // ii = ((affJtagPkg.bytesLeft / 4) + 1);
    for (i = 0; i < (affJtagPkg.bytesLeft / 4); i++) {
      if (affJtagPkg.wcb[i].u32 == REQUEST_WCB) {
        buf_set_u32(crd_ptr, 0, affJtagPkg.len[i].u32, affJtagPkg.tdo[i].u32);
      }
      LOG_DEBUG_IO("before (%d)buf_set_u32:0x%08x", i, affJtagPkg.tdo[i].u32);
      crd_ptr += sizeof(uint32_t);
    }
    axi_ffjtag_clear_pkg(&affJtagPkg);
  }
  err = jtag_read_buffer(buf, cmd->cmd.scan);
  if (buf) free(buf);

  if (tap_get_state() != tap_get_end_state())
    err = axi_ffjtag_execute_statemove(1);

  return err;

out_err:
  if (buf) free(buf);
  return err;
}

static void axi_ffjtag_execute_reset(struct jtag_command *cmd) {
  LOG_DEBUG_IO("reset trst: %i srst: %i", cmd->cmd.reset->trst,
               cmd->cmd.reset->srst);

  if (xlnx_axiffjtag_xvc->srst.line) {
    // gpiod_line_set_value(xlnx_axiffjtag_xvc->srst.line,
    // 					 cmd->cmd.reset->srst ? 0 : 1);
  }

  if (xlnx_axiffjtag_xvc->trst.line) {
    if (cmd->cmd.reset->trst) tap_set_state(TAP_RESET);

    // gpiod_line_set_value(xlnx_axiffjtag_xvc->trst.line,
    // 					 cmd->cmd.reset->trst ? 0 : 1);
  }
}

static void axi_ffjtag_execute_sleep(struct jtag_command *cmd) {
  LOG_DEBUG_IO("sleep %" PRIi32 "", cmd->cmd.sleep->us);
  usleep(cmd->cmd.sleep->us);
}

static int axi_ffjtag_execute_tms(struct jtag_command *cmd) {
  const size_t num_bits = cmd->cmd.tms->num_bits;
  const uint8_t *bits = cmd->cmd.tms->bits;
  size_t left, write;
  uint32_t tms;
  int err;

  LOG_DEBUG_IO("execute tms %zu", num_bits);

  left = num_bits;
  while (left) {
    write = MIN(XLNX_XVC_MAX_BITS, left);
    tms = buf_get_u32(bits, 0, write);
    err = axi_ffjtag_transact(write, tms, 0, NULL, NOT_REAL_SEND);
    if (err != ERROR_OK) return err;
    left -= write;
    bits += 4;
  };
  axi_ffjtag_transact(0, 0, 0, NULL, REAL_SEND);  // cahill add
  axi_ffjtag_clear_pkg(&affJtagPkg);
  return ERROR_OK;
}

static int axi_ffjtag_execute_command(struct jtag_command *cmd) {
  LOG_DEBUG_IO("%s: cmd->type: %u", __func__, cmd->type);
  switch (cmd->type) {
    case JTAG_STABLECLOCKS:
      return axi_ffjtag_execute_stableclocks(cmd);
    case JTAG_RUNTEST:
      return axi_ffjtag_execute_runtest(cmd);
    case JTAG_TLR_RESET:
      tap_set_end_state(cmd->cmd.statemove->end_state);
      return axi_ffjtag_execute_statemove(0);
    case JTAG_PATHMOVE:
      return axi_ffjtag_execute_pathmove(cmd);
    case JTAG_SCAN:
      return axi_ffjtag_execute_scan(cmd);
    case JTAG_RESET:
      axi_ffjtag_execute_reset(cmd);
      break;
    case JTAG_SLEEP:
      axi_ffjtag_execute_sleep(cmd);
      break;
    case JTAG_TMS:
      return axi_ffjtag_execute_tms(cmd);
    default:
      LOG_ERROR("BUG: Unknown JTAG command type encountered.");
      return ERROR_JTAG_QUEUE_FAILED;
  }

  return ERROR_OK;
}

static int axi_ffjtag_execute_queue(struct jtag_command *cmd_queue) {
  struct jtag_command *cmd = cmd_queue;
  int ret;

  while (cmd) {
    ret = axi_ffjtag_execute_command(cmd);

    if (ret != ERROR_OK) return ret;

    cmd = cmd->next;
  }

  return ERROR_OK;
}

static int axi_ffjtag_init(void) {
  uint32_t baseaddr;

  if (xlnx_axiffjtag_xvc->deviceaddr) {
    baseaddr = strtoul(xlnx_axiffjtag_xvc->deviceaddr, NULL, 0);
  } else {
    LOG_ERROR("Please set deviceaddr.");
    return ERROR_JTAG_INIT_FAILED;
  }

  xlnx_axiffjtag_xvc->fd = open("/dev/mem", O_RDWR | O_SYNC);
  if (xlnx_axiffjtag_xvc->fd < 0) {
    LOG_ERROR("Failed to open /dev/mem.  Check permissions.");
    return ERROR_JTAG_INIT_FAILED;
  }

  // xlnx_axiffjtag_xvc->baseaddr = mmap(0, XLNX_XVC_MAX_REG, PROT_READ |
  // PROT_WRITE, MAP_SHARED, xlnx_axiffjtag_xvc->fd, baseaddr);

#define MAP_SIZE 0x10000
  unsigned int pagesize = (unsigned)sysconf(_SC_PAGESIZE);
  xlnx_axiffjtag_xvc->ptr = (affJtag_t *)mmap(
      NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
      xlnx_axiffjtag_xvc->fd, baseaddr & ~((typeof(baseaddr))pagesize - 1));
  if (xlnx_axiffjtag_xvc->ptr == MAP_FAILED) {
    LOG_ERROR("mmap() failed.  Check permissions.");
    close(xlnx_axiffjtag_xvc->fd);
    return ERROR_JTAG_INIT_FAILED;
  }
  LOG_INFO("Mapped axiFFJtag vaddr %p paddr 0x%x", xlnx_axiffjtag_xvc->ptr,
           baseaddr);

  reset_affjtag(xlnx_axiffjtag_xvc->ptr, 100);
  reset_only_affjtag(xlnx_axiffjtag_xvc->ptr);
  axi_ffjtag_clear_pkg(&affJtagPkg);
  return ERROR_OK;
}

static int axi_ffjtag_quit(void) {
  int err;

  munmap(xlnx_axiffjtag_xvc->baseaddr, XLNX_XVC_MAX_REG);

  err = close(xlnx_axiffjtag_xvc->fd);
  if (err) return err;

  return ERROR_OK;
}

static int axi_ffjtag_speed(int speed) {
#define jtagMclk = (25000)
  LOG_INFO("int openocd12lts speed : %d", speed);
  // speed = n kHz
  set_affjtag_clk(xlnx_axiffjtag_xvc->ptr, (25000 / speed) * CLK_T);
  // reset_only_affjtag(xlnx_axiffjtag_xvc->ptr);
  return ERROR_OK;
}

static int axi_ffjtag_khz(int khz, int *jtag_speed) {
  LOG_INFO("axi_ffjtag_khz : %d", khz);
  *jtag_speed = khz;

  return ERROR_OK;
}

static int axi_ffjtag_div(int speed, int *khz) {
  LOG_INFO("axi_ffjtag_div : %d", speed);
  *khz = speed;

  return ERROR_OK;
}

COMMAND_HANDLER(axi_ffjtag_handle_devaddr_command) {
  if (CMD_ARGC < 1) return ERROR_COMMAND_SYNTAX_ERROR;

  /* we can't really free this in a safe manner, so at least
   * limit the memory we're leaking by freeing the old one first
   * before allocating a new one ...
   */
  if (xlnx_axiffjtag_xvc->deviceaddr) free(xlnx_axiffjtag_xvc->deviceaddr);

  xlnx_axiffjtag_xvc->deviceaddr = strdup(CMD_ARGV[0]);

  return ERROR_OK;
}

static const struct command_registration axi_ffjtag_command_handlers[] = {
    {
        .name = "axi_ffjtag_devaddr",
        .handler = axi_ffjtag_handle_devaddr_command,
        .mode = COMMAND_CONFIG,
        .help = "Configure XVC/AXI JTAG device memory address",
        .usage = "axi_ffjtag_devaddr <device address>",
    },

    COMMAND_REGISTRATION_DONE};

static struct jtag_interface axi_ffjtag_jtag_ops = {
    .execute_queue = &axi_ffjtag_execute_queue,
};

// affJtag swd operate!!!!

static int axi_ffjtag_sequence_swd(const uint8_t *seq, size_t length) {
  size_t left, write;
  uint32_t send;
  int err;

  left = length;
  while (left) {
    write = MIN(XLNX_XVC_MAX_BITS, left);
    send = buf_get_u32(seq, 0, write);
    err = axi_ffjtag_transact(write << 8, send, 0, NULL, NOT_REAL_SEND);
    if (err != ERROR_OK) return err;
    left -= write;
    seq += sizeof(uint32_t);
  };
  axi_ffjtag_transact(0, 0, 0, NULL, REAL_SEND);
  axi_ffjtag_clear_pkg(&affJtagPkg);
  return ERROR_OK;
}

static int axi_ffjtag_swd_switch_seq(enum swd_special_seq seq) {
  axi_ffjtag_clear_pkg(&affJtagPkg);
  switch (seq) {
    case LINE_RESET:  // 0
      LOG_DEBUG_IO("SWD line reset");
      return axi_ffjtag_sequence_swd(swd_seq_line_reset,
                                     swd_seq_line_reset_len);
    case JTAG_TO_SWD:  // 1
      LOG_DEBUG_IO("JTAG-to-SWD");
      return axi_ffjtag_sequence_swd(swd_seq_jtag_to_swd,
                                     swd_seq_jtag_to_swd_len);

    case JTAG_TO_DORMANT:  // 2
      LOG_DEBUG_IO("JTAG-to-DORMANT");
      return axi_ffjtag_sequence_swd(swd_seq_jtag_to_dormant,
                                     swd_seq_jtag_to_dormant_len);

    case SWD_TO_JTAG:  // 3
      LOG_DEBUG_IO("SWD-to-JTAG");
      return axi_ffjtag_sequence_swd(swd_seq_swd_to_jtag,
                                     swd_seq_swd_to_jtag_len);

    case SWD_TO_DORMANT:  // 4
      LOG_DEBUG_IO("SWD-to-DORMANT");
      return axi_ffjtag_sequence_swd(swd_seq_swd_to_dormant,
                                     swd_seq_swd_to_dormant_len);

    case DORMANT_TO_SWD:  // 5
      LOG_DEBUG_IO("DORMANT-to-SWD");
      return axi_ffjtag_sequence_swd(swd_seq_dormant_to_swd,
                                     swd_seq_dormant_to_swd_len);

    case DORMANT_TO_JTAG:  // 6
      LOG_DEBUG_IO("DORMANT-to-JTAG");
      return axi_ffjtag_sequence_swd(swd_seq_dormant_to_jtag,
                                     swd_seq_dormant_to_jtag_len);

    default:
      LOG_ERROR("Sequence %d not supported", seq);
      return ERROR_FAIL;
  }

  return ERROR_OK;
}

static int queued_retval;

static void axi_ffjtag_swd_write_reg(uint8_t cmd, uint32_t value,
                                     uint32_t ap_delay_clk);

static void swd_clear_sticky_errors(void) {
  axi_ffjtag_swd_write_reg(swd_cmd(false, false, DP_ABORT),
                           STKCMPCLR | STKERRCLR | WDERRCLR | ORUNERRCLR, 0);
}

static void axi_ffjtag_swd_read_reg(uint8_t cmd, uint32_t *value,
                                    uint32_t ap_delay_clk) {
  uint32_t res, res1, ack, rpar;
  int err;

  assert(cmd & SWD_CMD_RNW);
  LOG_DEBUG_IO("cmd(%d),ap_delay_clk(%08x)", cmd, ap_delay_clk);
  cmd |= SWD_CMD_START | SWD_CMD_PARK;
  /* cmd + ack */
  axi_ffjtag_clear_pkg(&affJtagPkg);
  err = axi_ffjtag_transact(8 << 8, cmd, 0, NULL, NOT_REAL_SEND);
  err = axi_ffjtag_transact(4 << 16, cmd, 0, &res, NOT_REAL_SEND);

  err = axi_ffjtag_transact(32 << 16, 0, 0, &res1, NOT_REAL_SEND);

  err = axi_ffjtag_transact(2 << 16, 0, 0, &rpar, REAL_SEND);
  if (err != ERROR_OK) goto err_out;
  res = affJtagPkg.tdo[0].u32;
  ack = MASK_ACK_axiffjtag(res);
  res = affJtagPkg.tdo[1].u32;
  rpar = affJtagPkg.tdo[2].u32;

  LOG_DEBUG_IO("%s %s %s reg %X = %08" PRIx32,
               ack == SWD_ACK_OK      ? "OK"
               : ack == SWD_ACK_WAIT  ? "WAIT"
               : ack == SWD_ACK_FAULT ? "FAULT"
                                      : "JUNK",
               cmd & SWD_CMD_APNDP ? "AP" : "DP",
               cmd & SWD_CMD_RNW ? "read" : "write", (cmd & SWD_CMD_A32) >> 1,
               res);
  switch (ack) {
    case SWD_ACK_OK:
      if (MASK_PAR(rpar) != parity_u32(res)) {
        LOG_DEBUG_IO("Wrong parity detected");
        queued_retval = ERROR_FAIL;
        return;
      }
      if (value) *value = res;
      if (cmd & SWD_CMD_APNDP) {
        axi_ffjtag_clear_pkg(&affJtagPkg);
        err = axi_ffjtag_transact(ap_delay_clk << 8, 0, 0, NULL, REAL_SEND);
      }
      queued_retval = err;
      return;
    case SWD_ACK_WAIT:
      LOG_DEBUG_IO("SWD_ACK_WAIT");
      swd_clear_sticky_errors();
      return;
    case SWD_ACK_FAULT:
      LOG_DEBUG_IO("SWD_ACK_FAULT");
      queued_retval = ack;
      return;
    default:
      LOG_DEBUG_IO("No valid acknowledge: ack=%02" PRIx32, ack);
      queued_retval = ack;
      return;
  }
err_out:
  queued_retval = err;
}

static void axi_ffjtag_swd_write_reg(uint8_t cmd, uint32_t value,
                                     uint32_t ap_delay_clk) {
  uint32_t res, ack;
  int err;

  assert(!(cmd & SWD_CMD_RNW));
  LOG_DEBUG_IO("cmd(%d),value(%08x),ap_delay_ck(%08x)", cmd, value,
               ap_delay_clk);
  cmd |= SWD_CMD_START | SWD_CMD_PARK;
  /* cmd + trn + ack */
  axi_ffjtag_clear_pkg(&affJtagPkg);
  axi_ffjtag_transact(8 << 8, cmd, 0, NULL, NOT_REAL_SEND);
  err = axi_ffjtag_transact(5 << 16, cmd, 0, &res, NOT_REAL_SEND);
  err = axi_ffjtag_transact(32 << 8, value, 0, NULL, NOT_REAL_SEND);
  err = axi_ffjtag_transact(1 << 8, parity_u32(value), 0, NULL, REAL_SEND);
  if (err != ERROR_OK) goto err_out;
  res = affJtagPkg.tdo[0].u32;
  ack = MASK_ACK_axiffjtag(res);

  LOG_DEBUG_IO("%s %s %s reg %X = %08" PRIx32,
               ack == SWD_ACK_OK      ? "OK"
               : ack == SWD_ACK_WAIT  ? "WAIT"
               : ack == SWD_ACK_FAULT ? "FAULT"
                                      : "JUNK",
               cmd & SWD_CMD_APNDP ? "AP" : "DP",
               cmd & SWD_CMD_RNW ? "read" : "write", (cmd & SWD_CMD_A32) >> 1,
               value);

  switch (ack) {
    case SWD_ACK_OK:
      if (cmd & SWD_CMD_APNDP) {
        axi_ffjtag_clear_pkg(&affJtagPkg);
        err = axi_ffjtag_transact(ap_delay_clk << 8, 0, 0, NULL, REAL_SEND);
      }
      queued_retval = err;
      return;
    case SWD_ACK_WAIT:
      LOG_DEBUG_IO("SWD_ACK_WAIT");
      swd_clear_sticky_errors();
      return;
    case SWD_ACK_FAULT:
      LOG_DEBUG_IO("SWD_ACK_FAULT");
      queued_retval = ack;
      return;
    default:
      LOG_DEBUG_IO("No valid acknowledge: ack=%02" PRIx32, ack);
      queued_retval = ack;
      return;
  }

err_out:
  queued_retval = err;
}

/* This code defines a function axi_ffjtag_swd_run_queue that runs queued
 * transactions for SWD communication. It ensures at least 8 idle cycles between
 * each transaction and clears the package before each transaction. It returns
 * the error code after processing the queued transaction. */

static int axi_ffjtag_swd_run_queue(void) {
  int err;
  LOG_DEBUG_IO("---> swd run queue");
  /* we want at least 8 idle cycles between each transaction */
  axi_ffjtag_clear_pkg(&affJtagPkg);
  err = axi_ffjtag_transact(8 << 8, 0, 0, NULL, REAL_SEND);
  if (err != ERROR_OK) return err;

  err = queued_retval;
  queued_retval = ERROR_OK;
  LOG_DEBUG_IO("SWD queue return value: %02x", err);

  return err;
}

static int axi_ffjtag_swd_init(void) { return ERROR_OK; }

static const struct swd_driver axi_ffjtag_swd_ops = {
    .init = axi_ffjtag_swd_init,
    .switch_seq = axi_ffjtag_swd_switch_seq,
    .read_reg = axi_ffjtag_swd_read_reg,
    .write_reg = axi_ffjtag_swd_write_reg,
    .run = axi_ffjtag_swd_run_queue,
};

static const char *const axi_ffjtag_transports[] = {"jtag", "swd", NULL};

struct adapter_driver xlnx_axi_FFJtag_adapter_driver = {
    .name = "axi_FFJtager",
    .transports = axi_ffjtag_transports,
    .commands = axi_ffjtag_command_handlers,

    .init = &axi_ffjtag_init,
    .quit = &axi_ffjtag_quit,
    .speed = &axi_ffjtag_speed,
    .khz = &axi_ffjtag_khz,
    .speed_div = &axi_ffjtag_div,

    .jtag_ops = &axi_ffjtag_jtag_ops,
    .swd_ops = &axi_ffjtag_swd_ops,
};
