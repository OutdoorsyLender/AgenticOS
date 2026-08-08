/*
 * fs_launcher — trusted launch boundary for AgenticOS Phase Zero (M3B).
 *
 * Single-threaded, no shell, no dynamic policy evaluation, direct Linux
 * UAPI only. Reads a bounded, versioned launch request on fd 0, blocks at a
 * launch gate until the controller verifies cgroup containment, then:
 * sanitizes FDs (close_range), opens policy roots with openat2 (trusted
 * resolution), builds a Landlock ruleset, sets PR_SET_NO_NEW_PRIVS, applies
 * landlock_restrict_self(), and execve()s the hostile worker.
 *
 * FAIL CLOSED on every setup failure: the worker is never exec'd unless the
 * full policy was applied. NOT A COMPLETE SANDBOX: this enforces filesystem
 * path policy only, under the separately-proven cgroup containment layer.
 *
 * Protocol (fd 0, text, length-prefixed values, all counts/sizes bounded):
 *   AOSLAUNCH/1\n
 *   nonce <len> <bytes>\n
 *   policy_digest <len> <hex bytes>\n
 *   min_abi <n>\n
 *   argv <count>\n  + <count> lines "<len> <bytes>\n"
 *   env <count>\n   + <count> lines "<len> <KEY=VALUE bytes>\n"
 *   cwd <dev> <ino> <len> <bytes>\n
 *   roots <count>\n + <count> lines
 *         "<mode>[flags] <dev> <ino> <len> <path bytes>\n"
 *   END\n
 *   (controller then writes a single gate byte 'G')
 *
 * mode: r=ro x=rx w=rw ; flags: f=allow MAKE_FIFO s=allow MAKE_SOCK
 *
 * Status channel (fd from AOS_STATUS_FD, moved to fd 3, CLOEXEC):
 *   R:<nonce>\n ready/at gate   S\n fds sanitized
 *   P\n policy prepared   N\n no_new_privs
 *   A:<abi>:<handled-mask-hex>:<policy-digest>\n restrict_self applied;
 *                                               launcher waits for 'X'
 *   E:<errno>\n  execve failed after policy applied
 *   F:<stage>:<errno>\n  setup failure — worker NEVER ran
 * On successful execve the status fd closes (CLOEXEC) => parent sees EOF.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <linux/close_range.h>
#include <linux/landlock.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* ---- Linux UAPI rights through ABI v3 ---- */
#define LLEXECUTE     LANDLOCK_ACCESS_FS_EXECUTE
#define LLWRITE_FILE  LANDLOCK_ACCESS_FS_WRITE_FILE
#define LLREAD_FILE   LANDLOCK_ACCESS_FS_READ_FILE
#define LLREAD_DIR    LANDLOCK_ACCESS_FS_READ_DIR
#define LLREMOVE_DIR  LANDLOCK_ACCESS_FS_REMOVE_DIR
#define LLREMOVE_FILE LANDLOCK_ACCESS_FS_REMOVE_FILE
#define LLMAKE_CHAR   LANDLOCK_ACCESS_FS_MAKE_CHAR
#define LLMAKE_DIR    LANDLOCK_ACCESS_FS_MAKE_DIR
#define LLMAKE_REG    LANDLOCK_ACCESS_FS_MAKE_REG
#define LLMAKE_SOCK   LANDLOCK_ACCESS_FS_MAKE_SOCK
#define LLMAKE_FIFO   LANDLOCK_ACCESS_FS_MAKE_FIFO
#define LLMAKE_BLOCK  LANDLOCK_ACCESS_FS_MAKE_BLOCK
#define LLMAKE_SYM    LANDLOCK_ACCESS_FS_MAKE_SYM
#define LLREFER       LANDLOCK_ACCESS_FS_REFER
#define LLTRUNCATE    LANDLOCK_ACCESS_FS_TRUNCATE

#define LL_ALL_V3 (LLEXECUTE | LLWRITE_FILE | LLREAD_FILE | LLREAD_DIR | \
                   LLREMOVE_DIR | LLREMOVE_FILE | LLMAKE_CHAR | LLMAKE_DIR | \
                   LLMAKE_REG | LLMAKE_SOCK | LLMAKE_FIFO | LLMAKE_BLOCK | \
                   LLMAKE_SYM | LLREFER | LLTRUNCATE)

#define LL_MODE_RO (LLREAD_FILE | LLREAD_DIR)
#define LL_MODE_RX (LLREAD_FILE | LLREAD_DIR | LLEXECUTE)
#define LL_MODE_RW (LLREAD_FILE | LLREAD_DIR | LLWRITE_FILE | LLTRUNCATE | \
                    LLREMOVE_FILE | LLREMOVE_DIR | LLMAKE_REG | LLMAKE_DIR | \
                    LLMAKE_SYM | LLREFER)

/* Rights applicable to regular files (M3A discovery: directory-only rights
 * on a file rule make landlock_add_rule fail with EINVAL). */
#define LL_FILE_RIGHTS (LLEXECUTE | LLREAD_FILE | LLWRITE_FILE | \
                        LLTRUNCATE)

#define PR_SET_NO_NEW_PRIVS   38

/* ---- protocol bounds ---- */
#define MAX_ITEMS 64
#define MAX_ITEM_LEN 4096
#define LINE_CAP (MAX_ITEM_LEN + 160)

/* ---- static request storage (no malloc) ---- */
static char g_argv_data[MAX_ITEMS][MAX_ITEM_LEN + 1];
static char *g_argv[MAX_ITEMS + 1];
static int g_argc;
static char g_env_data[MAX_ITEMS][MAX_ITEM_LEN + 1];
static char *g_envp[MAX_ITEMS + 1];
static int g_envc;
static char g_root_path[MAX_ITEMS][MAX_ITEM_LEN + 1];
static char g_root_mode[MAX_ITEMS];       /* 'r' | 'x' | 'w' */
static int g_root_fifo[MAX_ITEMS];
static int g_root_sock[MAX_ITEMS];
static uint64_t g_root_dev[MAX_ITEMS];
static uint64_t g_root_ino[MAX_ITEMS];
static int g_rootc;
static char g_cwd[MAX_ITEM_LEN + 1];
static uint64_t g_cwd_dev;
static uint64_t g_cwd_ino;
static char g_nonce[MAX_ITEM_LEN + 1];
static char g_policy_digest[65];
static long g_min_abi = 3;

static int g_status_fd = -1;

static void fail_closed(const char *stage, int err);

/* ---- small helpers ---- */

static void status_raw(const char *buf, size_t len)
{
    if (g_status_fd < 0)
        return;
    while (len > 0) {
        ssize_t n = write(g_status_fd, buf, len);
        if (n <= 0) {
            if (errno == EINTR)
                continue;
            return;
        }
        buf += n;
        len -= (size_t)n;
    }
}

static void status_letter(char c)
{
    char record[2] = {c, '\n'};
    status_raw(record, sizeof(record));
}

static void status_ready(void)
{
    status_raw("R:", 2);
    status_raw(g_nonce, strlen(g_nonce));
    status_raw("\n", 1);
}

static void status_applied(long abi, int corrupt_digest)
{
    char record[128];
    const char *digest = corrupt_digest
        ? "0000000000000000000000000000000000000000000000000000000000000000"
        : g_policy_digest;
    int len = snprintf(record, sizeof(record), "A:%ld:%llx:%s\n", abi,
                       (unsigned long long)LL_ALL_V3, digest);
    if (len < 0 || (size_t)len >= sizeof(record))
        fail_closed("status", EOVERFLOW);
    status_raw(record, (size_t)len);
}

static void fail_closed(const char *stage, int err)
{
    /* F:<stage>:<errno>\n — worker is never exec'd after this. */
    char msg[96];
    int len = 0;
    const char *p = stage;
    msg[len++] = 'F';
    msg[len++] = ':';
    while (*p && len < 80)
        msg[len++] = *p++;
    msg[len++] = ':';
    if (err < 0)
        err = -err;
    if (err >= 100)
        msg[len++] = (char)('0' + (err / 100) % 10);
    if (err >= 10)
        msg[len++] = (char)('0' + (err / 10) % 10);
    msg[len++] = (char)('0' + err % 10);
    msg[len++] = '\n';
    status_raw(msg, (size_t)len);
    _exit(2);
}

static int read_byte(int fd, char *out)
{
    for (;;) {
        ssize_t n = read(fd, out, 1);
        if (n == 1)
            return 0;
        if (n == 0)
            return -1;      /* EOF */
        if (errno == EINTR)
            continue;
        return -1;
    }
}

/* Read one '\n'-terminated line, unbuffered (gate byte must not be eaten). */
static int read_line(int fd, char *buf, size_t cap)
{
    size_t len = 0;
    for (;;) {
        char c;
        if (read_byte(fd, &c) != 0)
            return -1;
        if (c == '\n') {
            buf[len] = '\0';
            return (int)len;
        }
        if (len >= cap - 1)
            return -2;      /* oversized */
        buf[len++] = c;
    }
}

static long parse_long(const char *s, int *ok)
{
    long v = 0;
    *ok = 0;
    if (!*s)
        return 0;
    while (*s) {
        if (*s < '0' || *s > '9')
            return 0;
        int digit = *s - '0';
        const long limit = 1L << 30;
        if (v > (limit - digit) / 10)
            return 0;
        v = v * 10 + digit;
        s++;
    }
    *ok = 1;
    return v;
}

static uint64_t parse_u64_token(const char *s, size_t len, int *ok)
{
    uint64_t value = 0;
    *ok = 0;
    if (len == 0)
        return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned int digit;
        if (s[i] < '0' || s[i] > '9')
            return 0;
        digit = (unsigned int)(s[i] - '0');
        if (value > (UINT64_MAX - digit) / 10)
            return 0;
        value = value * 10 + digit;
    }
    *ok = 1;
    return value;
}

/* "<len> <value>" inline in one line; value may contain spaces but never
 * '\n' (the controller rejects such inputs). Length must match exactly. */
static int parse_len_value(const char *line, char *dst, size_t dstcap)
{
    const char *sp = strchr(line, ' ');
    if (!sp)
        return -1;
    char lenbuf[16];
    size_t toklen = (size_t)(sp - line);
    if (toklen == 0 || toklen >= sizeof(lenbuf))
        return -1;
    memcpy(lenbuf, line, toklen);
    lenbuf[toklen] = '\0';
    int ok;
    long len = parse_long(lenbuf, &ok);
    const char *value = sp + 1;
    size_t vlen = strlen(value);
    if (!ok || len < 0 || (size_t)len != vlen || vlen >= dstcap)
        return -1;
    memcpy(dst, value, vlen + 1);
    return 0;
}

/* "<dev> <ino> <len> <path>" */
static int parse_identity_value(const char *line, uint64_t *dev,
                                uint64_t *ino, char *dst, size_t dstcap)
{
    const char *dev_end = strchr(line, ' ');
    const char *ino_start;
    const char *ino_end;
    int ok;

    if (!dev_end)
        return -1;
    ino_start = dev_end + 1;
    ino_end = strchr(ino_start, ' ');
    if (!ino_end)
        return -1;
    *dev = parse_u64_token(line, (size_t)(dev_end - line), &ok);
    if (!ok)
        return -1;
    *ino = parse_u64_token(ino_start, (size_t)(ino_end - ino_start), &ok);
    if (!ok)
        return -1;
    return parse_len_value(ino_end + 1, dst, dstcap);
}

static void parse_request(void)
{
    char line[LINE_CAP];
    int n;
    int seen_nonce = 0;
    int seen_digest = 0;
    int seen_min_abi = 0;
    int seen_argv = 0;
    int seen_env = 0;
    int seen_cwd = 0;
    int seen_roots = 0;

    n = read_line(0, line, sizeof(line));
    if (n != 11 || memcmp(line, "AOSLAUNCH/1", 11) != 0)
        fail_closed("parse", EPROTO);

    for (;;) {
        n = read_line(0, line, sizeof(line));
        if (n == -2)
            fail_closed("parse", E2BIG);
        if (n < 0)
            fail_closed("parse", EPROTO);

        if (memcmp(line, "nonce ", 6) == 0) {
            if (seen_nonce++)
                fail_closed("parse", EPROTO);
            if (parse_len_value(line + 6, g_nonce, sizeof(g_nonce)) != 0)
                fail_closed("parse", EPROTO);
        } else if (memcmp(line, "policy_digest ", 14) == 0) {
            if (seen_digest++)
                fail_closed("parse", EPROTO);
            if (parse_len_value(line + 14, g_policy_digest,
                                sizeof(g_policy_digest)) != 0)
                fail_closed("parse", EPROTO);
        } else if (memcmp(line, "min_abi ", 8) == 0) {
            if (seen_min_abi++)
                fail_closed("parse", EPROTO);
            int ok;
            g_min_abi = parse_long(line + 8, &ok);
            if (!ok || g_min_abi < 1 || g_min_abi > 64)
                fail_closed("parse", EPROTO);
        } else if (memcmp(line, "argv ", 5) == 0) {
            if (seen_argv++)
                fail_closed("parse", EPROTO);
            int ok;
            long count = parse_long(line + 5, &ok);
            if (!ok || count < 1 || count > MAX_ITEMS)
                fail_closed("parse", EPROTO);
            g_argc = (int)count;
            for (int i = 0; i < g_argc; i++) {
                n = read_line(0, line, sizeof(line));
                if (n < 0)
                    fail_closed("parse", EPROTO);
                if (parse_len_value(line, g_argv_data[i], MAX_ITEM_LEN + 1) != 0)
                    fail_closed("parse", EPROTO);
                g_argv[i] = g_argv_data[i];
            }
            g_argv[g_argc] = NULL;
        } else if (memcmp(line, "env ", 4) == 0) {
            if (seen_env++)
                fail_closed("parse", EPROTO);
            int ok;
            long count = parse_long(line + 4, &ok);
            if (!ok || count < 0 || count > MAX_ITEMS)
                fail_closed("parse", EPROTO);
            g_envc = (int)count;
            for (int i = 0; i < g_envc; i++) {
                n = read_line(0, line, sizeof(line));
                if (n < 0)
                    fail_closed("parse", EPROTO);
                if (parse_len_value(line, g_env_data[i], MAX_ITEM_LEN + 1) != 0)
                    fail_closed("parse", EPROTO);
                g_envp[i] = g_env_data[i];
            }
            g_envp[g_envc] = NULL;
        } else if (memcmp(line, "cwd ", 4) == 0) {
            if (seen_cwd++)
                fail_closed("parse", EPROTO);
            if (parse_identity_value(line + 4, &g_cwd_dev, &g_cwd_ino,
                                     g_cwd, sizeof(g_cwd)) != 0)
                fail_closed("parse", EPROTO);
        } else if (memcmp(line, "roots ", 6) == 0) {
            if (seen_roots++)
                fail_closed("parse", EPROTO);
            int ok;
            long count = parse_long(line + 6, &ok);
            if (!ok || count < 0 || count > MAX_ITEMS)
                fail_closed("parse", EPROTO);
            g_rootc = (int)count;
            for (int i = 0; i < g_rootc; i++) {
                n = read_line(0, line, sizeof(line));
                if (n < 2)
                    fail_closed("parse", EPROTO);
                /* "<mode>[flags] <len> <path>" — split at last space that
                 * precedes the length token: flags are short, so scan the
                 * mode/flags token up to the first space. */
                char *sp = strchr(line, ' ');
                if (!sp || sp == line || (sp - line) > 8)
                    fail_closed("parse", EPROTO);
                char mode = line[0];
                if (mode != 'r' && mode != 'x' && mode != 'w')
                    fail_closed("parse", EPROTO);
                g_root_mode[i] = mode;
                for (char *f = line + 1; f < sp; f++) {
                    if (*f == 'f')
                        g_root_fifo[i] = 1;
                    else if (*f == 's')
                        g_root_sock[i] = 1;
                    else
                        fail_closed("parse", EPROTO);
                }
                if (parse_identity_value(sp + 1, &g_root_dev[i],
                                         &g_root_ino[i], g_root_path[i],
                                         MAX_ITEM_LEN + 1) != 0)
                    fail_closed("parse", EPROTO);
            }
        } else if (strcmp(line, "END") == 0) {
            break;
        } else {
            fail_closed("parse", EPROTO);
        }
    }
    if (!seen_nonce || !seen_digest || !seen_min_abi || !seen_argv ||
        !seen_env || !seen_cwd || !seen_roots || g_argc < 1 ||
        g_cwd[0] == '\0' || g_nonce[0] == '\0' ||
        strlen(g_policy_digest) != 64)
        fail_closed("parse", EPROTO);
}

/* Trusted open: openat2 with no symlink/magiclink resolution, O_PATH.
 * Bounded retry on EAGAIN only; everything else fails closed. */
static int trusted_open(int base_fd, const char *path, int extra_oflags,
                        uint64_t expected_dev, uint64_t expected_ino)
{
    struct open_how how;
    struct stat st;
    const char *relative;

    if (path[0] != '/')
        fail_closed("resolve", EINVAL);
    relative = path;
    while (*relative == '/')
        relative++;
    if (*relative == '\0')
        relative = ".";
    memset(&how, 0, sizeof(how));
    how.flags = O_PATH | O_CLOEXEC | O_NOFOLLOW | extra_oflags;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS |
                  RESOLVE_NO_SYMLINKS;
    for (int attempt = 0; attempt < 3; attempt++) {
        int fd = (int)syscall(SYS_openat2, base_fd, relative, &how,
                              sizeof(how));
        if (fd >= 0) {
            if (fstat(fd, &st) != 0)
                fail_closed("resolve", errno);
            if ((uint64_t)st.st_dev != expected_dev ||
                (uint64_t)st.st_ino != expected_ino)
                fail_closed("resolve_identity", ESTALE);
            return fd;
        }
        if (errno == EAGAIN)
            continue;
        fail_closed("resolve", errno);
    }
    fail_closed("resolve", EAGAIN);
    return -1; /* unreachable */
}

int main(void)
{
    const char *sfd = getenv("AOS_STATUS_FD");
    if (sfd) {
        int ok0;
        long fdnum = parse_long(sfd, &ok0);
        if (ok0 && fdnum >= 0 && fdnum <= 1024)
            g_status_fd = (int)fdnum;
    }

    parse_request();

    if (g_status_fd < 3 || fcntl(g_status_fd, F_GETFD) < 0)
        fail_closed("statusfd", EBADF);

    /* Landlock ABI probe: runtime truth, not kernel-version inference. */
    long abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
                       LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0)
        fail_closed("abi", errno);
    if (abi < g_min_abi)
        fail_closed("abi", EOPNOTSUPP);

    status_ready();                      /* at the launch gate */

    char gate;
    if (read_byte(0, &gate) != 0 || gate != 'G')
        fail_closed("gate", EACCES);

    const char *fault = getenv("AOS_LAUNCHER_FAULT_INJECT");
    if (fault && strncmp(fault, "sleep_after_gate:", 17) == 0) {
        int okf;
        long secs = parse_long(fault + 17, &okf);
        if (okf && secs > 0 && secs < 3600)
            sleep((unsigned int)secs);
    }

    /* Phase 1 FD hygiene: keep 0,1,2 + status at fd 3 + a CLOEXEC copy
     * of the controller pipe at fd 4 for the post-policy exec gate. */
    if (g_status_fd != 3) {
        if (dup2(g_status_fd, 3) < 0)
            fail_closed("fdsanitize", errno);
        g_status_fd = 3;
    }
    if (fcntl(g_status_fd, F_SETFD, FD_CLOEXEC) != 0)
        fail_closed("fdsanitize", errno);
    if (dup2(0, 4) < 0)
        fail_closed("fdsanitize", errno);
    if (fcntl(4, F_SETFD, FD_CLOEXEC) != 0)
        fail_closed("fdsanitize", errno);
    if (syscall(SYS_close_range, 5, ~0u, 0) != 0)
        fail_closed("fdsanitize", errno);
    status_letter('S');

    int nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (nullfd < 0)
        fail_closed("fdsanitize", errno);

    int base_fd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (base_fd < 0)
        fail_closed("resolve", errno);

    /* Trusted open of every identity-bound policy root + cwd. */
    int root_fds[MAX_ITEMS];
    int cwd_fd = trusted_open(base_fd, g_cwd, O_DIRECTORY,
                              g_cwd_dev, g_cwd_ino);
    for (int i = 0; i < g_rootc; i++)
        root_fds[i] = trusted_open(base_fd, g_root_path[i], 0,
                                   g_root_dev[i], g_root_ino[i]);

    struct landlock_ruleset_attr rattr;
    rattr.handled_access_fs = LL_ALL_V3;
    if (fault && strcmp(fault, "fail_ruleset") == 0)
        fail_closed("ruleset", EIO);
    int ruleset_fd = (int)syscall(SYS_landlock_create_ruleset, &rattr,
                                  sizeof(rattr), 0);
    if (ruleset_fd < 0)
        fail_closed("ruleset", errno);

    for (int i = 0; i < g_rootc; i++) {
        uint64_t mask;
        switch (g_root_mode[i]) {
        case 'r': mask = LL_MODE_RO; break;
        case 'x': mask = LL_MODE_RX; break;
        default:  mask = LL_MODE_RW; break;
        }
        if (g_root_fifo[i])
            mask |= LLMAKE_FIFO;
        if (g_root_sock[i])
            mask |= LLMAKE_SOCK;
        /* MAKE_CHAR / MAKE_BLOCK are never granted by any mode. */
        struct stat st;
        if (fstat(root_fds[i], &st) != 0)
            fail_closed("resolve", errno);
        if (!S_ISDIR(st.st_mode))
            mask &= LL_FILE_RIGHTS;     /* M3A no-regress rule */
        struct landlock_path_beneath_attr pb;
        pb.allowed_access = mask & LL_ALL_V3;
        pb.parent_fd = root_fds[i];
        if (fault && strcmp(fault, "fail_rule") == 0)
            fail_closed("rule", EIO);
        if (syscall(SYS_landlock_add_rule, ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH, &pb, 0) != 0)
            fail_closed("rule", errno);
    }
    status_letter('P');

    if (fchdir(cwd_fd) != 0)
        fail_closed("cwd", errno);

    if (fault && strcmp(fault, "fail_nnp") == 0)
        fail_closed("nnp", EPERM);
    if (!(fault && strcmp(fault, "skip_nnp") == 0)) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
            fail_closed("nnp", errno);
        status_letter('N');
    }

    if (fault && strcmp(fault, "fail_restrict") == 0)
        fail_closed("restrict", EPERM);
    if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) != 0)
        fail_closed("restrict", errno);

    /* Final setup before acknowledgement: all root/ruleset/null descriptors
     * above fd 4 are closed.  fd 4 is the trusted controller's exec gate. */
    if (dup2(nullfd, 0) < 0)
        fail_closed("fdsanitize", errno);
    if (syscall(SYS_close_range, 5, ~0u, 0) != 0)
        fail_closed("fdsanitize", errno);

    status_applied(abi, fault && strcmp(fault, "bad_policy_digest_ack") == 0);

    /* Hostile exec requires positive controller validation of the complete
     * authenticated acknowledgement.  EOF, timeout-side closure, or any
     * other byte fails closed after Landlock is already active. */
    if (read_byte(4, &gate) != 0 || gate != 'X')
        fail_closed("execgate", EACCES);
    if (close(4) != 0)
        fail_closed("fdsanitize", errno);

    execve(g_argv[0], g_argv, g_envp);
    /* Only reached when execve FAILS (policy already applied — still safe).
     * Distinct E:<errno> + exit 127: never a generic worker exit. */
    {
        int e = errno;
        char msg[24];
        int len = 0;
        msg[len++] = 'E';
        msg[len++] = ':';
        if (e >= 100)
            msg[len++] = (char)('0' + (e / 100) % 10);
        if (e >= 10)
            msg[len++] = (char)('0' + (e / 10) % 10);
        msg[len++] = (char)('0' + e % 10);
        msg[len++] = '\n';
        status_raw(msg, (size_t)len);
    }
    _exit(127);
    return 0;
}
