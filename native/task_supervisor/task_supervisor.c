/*
 * AgenticOS same-scope task supervisor.
 *
 * This program implements exactly one bounded operation.  Its argv contract is:
 *
 *   AOSSUP/1
 *   bwrap_fd 5
 *   status_fd 6
 *   broker_passc <canonical-positive-decimal>
 *   broker_pass <broker-only FD numbers...>
 *   worker_passc <canonical-nonnegative-decimal>
 *   worker_pass <worker-only FD numbers...>
 *   broker_argc <canonical-positive-decimal>
 *   broker <broker argv items...>
 *   worker_argc <canonical-positive-decimal>
 *   worker <worker argv items...>
 *   END
 *
 * Both executable vectors must start with the literal argv[0] "bwrap".
 * Descriptor 5 is an already identity-opened executable capability.  Descriptor
 * 6 is the write end of a controller-owned pipe.  Neither a pathname nor PATH
 * is consulted for either exec: both use execveat(AT_EMPTY_PATH) on descriptor
 * 5 with the fixed environment below.
 *
 * The only success record is:
 *
 *   AOSSUP/1 BROKER_PID <canonical-positive-decimal>\n
 *
 * Errors use:
 *
 *   AOSSUP/1 ERROR <bounded-stage> <canonical-errno>\n
 *
 * Every record is emitted by one write no larger than PIPE_BUF.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/close_range.h>
#include <linux/kcmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SUPERVISOR_VERSION "AOSSUP/1"
#define BWRAP_FD 5
#define STATUS_FD 6
#define MAX_VECTOR_ITEMS 128U
#define MAX_ITEM_LENGTH 4096U
#define MAX_STATUS_RECORD 128U
#define MIN_PASS_FD 8

static const int required_broker_pass_fds[] = {
    8, 20, 21, 22, 23, 30, 31, 32, 33, 34
};

#define REQUIRED_BROKER_PASS_BASE_COUNT 9U
#define REQUIRED_BROKER_PASS_FIXTURE_COUNT 10U

struct contract {
    int broker_pass_fds[MAX_VECTOR_ITEMS];
    int worker_pass_fds[MAX_VECTOR_ITEMS];
    char *broker_argv[MAX_VECTOR_ITEMS + 1U];
    char *worker_argv[MAX_VECTOR_ITEMS + 1U];
    size_t broker_passc;
    size_t worker_passc;
    size_t broker_argc;
    size_t worker_argc;
};

enum child_failure_stage {
    CHILD_FAILURE_PARTITION = 1,
    CHILD_FAILURE_EXEC = 2,
};

struct child_failure {
    int stage;
    int error_number;
};

static char *const minimal_environment[] = {
    (char *)"LANG=C.UTF-8",
    (char *)"LC_ALL=C.UTF-8",
    NULL,
};

static int set_sigpipe(void (*handler)(int))
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    if (sigemptyset(&action.sa_mask) != 0) {
        return -1;
    }
    return sigaction(SIGPIPE, &action, NULL);
}

static bool exact_token(const char *observed, const char *expected)
{
    return observed != NULL && strcmp(observed, expected) == 0;
}

static bool bounded_item(const char *item)
{
    size_t length;

    if (item == NULL) {
        return false;
    }
    length = strnlen(item, MAX_ITEM_LENGTH + 1U);
    if (length == 0U || length > MAX_ITEM_LENGTH) {
        return false;
    }
    return strchr(item, '\n') == NULL && strchr(item, '\r') == NULL;
}

static bool parse_positive_decimal(const char *text, size_t maximum, size_t *value)
{
    size_t parsed = 0U;
    size_t index;
    size_t length;

    if (text == NULL || value == NULL) {
        return false;
    }
    length = strlen(text);
    if (length == 0U || (length > 1U && text[0] == '0')) {
        return false;
    }
    for (index = 0U; index < length; ++index) {
        unsigned int digit;

        if (text[index] < '0' || text[index] > '9') {
            return false;
        }
        digit = (unsigned int)(text[index] - '0');
        if (parsed > (maximum - digit) / 10U) {
            return false;
        }
        parsed = parsed * 10U + digit;
    }
    if (parsed == 0U || parsed > maximum) {
        return false;
    }
    *value = parsed;
    return true;
}

static bool parse_nonnegative_decimal(
    const char *text,
    size_t maximum,
    size_t *value)
{
    size_t parsed = 0U;
    size_t index;
    size_t length;

    if (text == NULL || value == NULL) {
        return false;
    }
    length = strlen(text);
    if (length == 0U || (length > 1U && text[0] == '0')) {
        return false;
    }
    for (index = 0U; index < length; ++index) {
        unsigned int digit;

        if (text[index] < '0' || text[index] > '9') {
            return false;
        }
        digit = (unsigned int)(text[index] - '0');
        if (parsed > (maximum - digit) / 10U) {
            return false;
        }
        parsed = parsed * 10U + digit;
    }
    if (parsed > maximum) {
        return false;
    }
    *value = parsed;
    return true;
}

static bool take_token(int argc, char **argv, size_t *cursor, const char *expected)
{
    if (*cursor >= (size_t)argc || !exact_token(argv[*cursor], expected)) {
        return false;
    }
    *cursor += 1U;
    return true;
}

static bool take_fixed_fd(
    int argc,
    char **argv,
    size_t *cursor,
    const char *role,
    const char *number)
{
    return take_token(argc, argv, cursor, role)
        && take_token(argc, argv, cursor, number);
}

static bool take_vector(
    int argc,
    char **argv,
    size_t *cursor,
    const char *count_role,
    const char *separator,
    char **destination,
    size_t *count_out)
{
    size_t count;
    size_t index;

    if (!take_token(argc, argv, cursor, count_role)
        || *cursor >= (size_t)argc
        || !parse_positive_decimal(argv[*cursor], MAX_VECTOR_ITEMS, &count)) {
        return false;
    }
    *cursor += 1U;
    if (!take_token(argc, argv, cursor, separator)
        || count > (size_t)argc - *cursor) {
        return false;
    }
    for (index = 0U; index < count; ++index) {
        if (!bounded_item(argv[*cursor + index])) {
            return false;
        }
        destination[index] = argv[*cursor + index];
    }
    destination[count] = NULL;
    *cursor += count;
    *count_out = count;
    return count > 0U && exact_token(destination[0], "bwrap");
}

static bool take_fd_vector(
    int argc,
    char **argv,
    size_t *cursor,
    const char *count_role,
    const char *separator,
    int *destination,
    size_t *count_out,
    bool allow_empty)
{
    size_t count;
    size_t index;

    if (!take_token(argc, argv, cursor, count_role)
        || *cursor >= (size_t)argc
        || !parse_nonnegative_decimal(
            argv[*cursor], MAX_VECTOR_ITEMS, &count)) {
        return false;
    }
    *cursor += 1U;
    if ((!allow_empty && count == 0U)
        || !take_token(argc, argv, cursor, separator)
        || count > (size_t)argc - *cursor) {
        return false;
    }
    for (index = 0U; index < count; ++index) {
        size_t parsed;

        if (!parse_positive_decimal(
                argv[*cursor + index], (size_t)INT_MAX, &parsed)
            || parsed < (size_t)MIN_PASS_FD
            || (index > 0U
                && parsed <= (size_t)destination[index - 1U])) {
            return false;
        }
        destination[index] = (int)parsed;
    }
    *cursor += count;
    *count_out = count;
    return true;
}

static bool pass_roles_are_exact(const struct contract *parsed)
{
    size_t index;
    size_t worker_index;

    if (parsed->broker_passc != REQUIRED_BROKER_PASS_BASE_COUNT
        && parsed->broker_passc != REQUIRED_BROKER_PASS_FIXTURE_COUNT) {
        return false;
    }
    for (index = 0U; index < parsed->broker_passc; ++index) {
        if (parsed->broker_pass_fds[index]
            != required_broker_pass_fds[index]) {
            return false;
        }
    }
    for (index = 0U; index < parsed->broker_passc; ++index) {
        for (worker_index = 0U;
             worker_index < parsed->worker_passc;
             ++worker_index) {
            if (parsed->broker_pass_fds[index]
                == parsed->worker_pass_fds[worker_index]) {
                return false;
            }
        }
    }
    return true;
}

static bool parse_contract(int argc, char **argv, struct contract *parsed)
{
    size_t cursor = 1U;

    if (parsed == NULL
        || argc < 21
        || (size_t)argc > 4U * MAX_VECTOR_ITEMS + 20U) {
        return false;
    }
    memset(parsed, 0, sizeof(*parsed));
    if (!take_token(argc, argv, &cursor, SUPERVISOR_VERSION)
        || !take_fixed_fd(argc, argv, &cursor, "bwrap_fd", "5")
        || !take_fixed_fd(argc, argv, &cursor, "status_fd", "6")
        || !take_fd_vector(
            argc,
            argv,
            &cursor,
            "broker_passc",
            "broker_pass",
            parsed->broker_pass_fds,
            &parsed->broker_passc,
            false)
        || !take_fd_vector(
            argc,
            argv,
            &cursor,
            "worker_passc",
            "worker_pass",
            parsed->worker_pass_fds,
            &parsed->worker_passc,
            true)
        || !pass_roles_are_exact(parsed)
        || !take_vector(
            argc,
            argv,
            &cursor,
            "broker_argc",
            "broker",
            parsed->broker_argv,
            &parsed->broker_argc)
        || !take_vector(
            argc,
            argv,
            &cursor,
            "worker_argc",
            "worker",
            parsed->worker_argv,
            &parsed->worker_argc)
        || !take_token(argc, argv, &cursor, "END")
        || cursor != (size_t)argc) {
        return false;
    }
    return true;
}

static int mark_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);

    if (flags < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
        return -1;
    }
    flags = fcntl(fd, F_GETFD);
    if (flags < 0 || (flags & FD_CLOEXEC) == 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int validate_descriptors(void)
{
    struct stat executable_status;
    struct stat pipe_status;
    int executable_flags;
    int status_flags;
    long pipe_buf;

    if (BWRAP_FD == STATUS_FD) {
        errno = EINVAL;
        return -1;
    }
    if (fstat(BWRAP_FD, &executable_status) != 0
        || !S_ISREG(executable_status.st_mode)
        || (executable_status.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0
        || (executable_status.st_mode & (S_ISUID | S_ISGID)) != 0) {
        errno = EBADF;
        return -1;
    }
    executable_flags = fcntl(BWRAP_FD, F_GETFL);
    if (executable_flags < 0
        || (((executable_flags & O_PATH) != O_PATH)
            && ((executable_flags & O_ACCMODE) != O_RDONLY))) {
        errno = EBADF;
        return -1;
    }
    if (fstat(STATUS_FD, &pipe_status) != 0 || !S_ISFIFO(pipe_status.st_mode)) {
        errno = EBADF;
        return -1;
    }
    status_flags = fcntl(STATUS_FD, F_GETFL);
    if (status_flags < 0
        || (status_flags & O_ACCMODE) != O_WRONLY
        || (status_flags & (O_NONBLOCK | O_APPEND)) != 0) {
        errno = EBADF;
        return -1;
    }
    pipe_buf = fpathconf(STATUS_FD, _PC_PIPE_BUF);
    if (pipe_buf < (long)MAX_STATUS_RECORD) {
        errno = EINVAL;
        return -1;
    }
    if (mark_cloexec(BWRAP_FD) != 0 || mark_cloexec(STATUS_FD) != 0) {
        return -1;
    }
    return 0;
}

static int validate_pass_descriptors(const struct contract *parsed)
{
    size_t index;
    size_t worker_index;
    pid_t self = getpid();

    for (index = 0U; index < parsed->broker_passc; ++index) {
        if (fcntl(parsed->broker_pass_fds[index], F_GETFD) < 0) {
            return -1;
        }
    }
    for (index = 0U; index < parsed->worker_passc; ++index) {
        if (fcntl(parsed->worker_pass_fds[index], F_GETFD) < 0) {
            return -1;
        }
    }
    for (index = 0U; index < parsed->broker_passc; ++index) {
        for (worker_index = 0U;
             worker_index < parsed->worker_passc;
             ++worker_index) {
            long comparison = syscall(
                SYS_kcmp,
                self,
                self,
                KCMP_FILE,
                (unsigned long)parsed->broker_pass_fds[index],
                (unsigned long)parsed->worker_pass_fds[worker_index]);

            if (comparison < 0) {
                return -1;
            }
            if (comparison == 0) {
                errno = EINVAL;
                return -1;
            }
        }
    }
    return 0;
}

static int mark_unclassified_cloexec(void)
{
    return (int)syscall(
        SYS_close_range,
        3U,
        ~0U,
        CLOSE_RANGE_CLOEXEC);
}

static int clear_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);

    if (flags < 0 || fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) != 0) {
        return -1;
    }
    flags = fcntl(fd, F_GETFD);
    if (flags < 0 || (flags & FD_CLOEXEC) != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int close_once(int fd)
{
    if (close(fd) != 0) {
        return -1;
    }
    return 0;
}

static int partition_branch(
    const int *close_fds,
    size_t close_count,
    const int *pass_fds,
    size_t pass_count)
{
    size_t index;

    for (index = 0U; index < close_count; ++index) {
        if (close_once(close_fds[index]) != 0) {
            return -1;
        }
    }
    for (index = 0U; index < pass_count; ++index) {
        if (clear_cloexec(pass_fds[index]) != 0) {
            return -1;
        }
    }
    return 0;
}

static int atomic_write(int fd, const void *buffer, size_t length)
{
    ssize_t result;

    do {
        result = write(fd, buffer, length);
    } while (result < 0 && errno == EINTR);
    if (result < 0) {
        return -1;
    }
    if ((size_t)result != length) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int report_record(const char *stage, pid_t broker_pid, int error_number)
{
    char record[MAX_STATUS_RECORD];
    int length;

    if (stage == NULL) {
        length = snprintf(
            record,
            sizeof(record),
            SUPERVISOR_VERSION " BROKER_PID %ld\n",
            (long)broker_pid);
    } else {
        length = snprintf(
            record,
            sizeof(record),
            SUPERVISOR_VERSION " ERROR %s %d\n",
            stage,
            error_number);
    }
    if (length <= 0 || (size_t)length >= sizeof(record)) {
        errno = EOVERFLOW;
        return -1;
    }
    return atomic_write(STATUS_FD, record, (size_t)length);
}

static void report_stderr(const char *stage, int error_number)
{
    char record[MAX_STATUS_RECORD];
    int length = snprintf(
        record,
        sizeof(record),
        SUPERVISOR_VERSION " ERROR %s %d\n",
        stage,
        error_number);

    if (length > 0 && (size_t)length < sizeof(record)) {
        (void)atomic_write(STDERR_FILENO, record, (size_t)length);
    }
}

static int wait_exact(pid_t pid)
{
    int status;
    pid_t result;

    do {
        result = waitpid(pid, &status, 0);
    } while (result < 0 && errno == EINTR);
    return result == pid ? 0 : -1;
}

static void kill_and_reap(pid_t pid)
{
    int kill_result;

    do {
        kill_result = kill(pid, SIGKILL);
    } while (kill_result != 0 && errno == EINTR);
    if (kill_result != 0 && errno != ESRCH) {
        /* Reaping is still mandatory even when the signal operation failed. */
    }
    (void)wait_exact(pid);
}

static int read_child_failure(int fd, struct child_failure *failure)
{
    unsigned char *output = (unsigned char *)failure;
    size_t offset = 0U;

    while (offset < sizeof(*failure)) {
        ssize_t result = read(fd, output + offset, sizeof(*failure) - offset);
        if (result == 0) {
            return offset == 0U ? 0 : -1;
        }
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        offset += (size_t)result;
    }
    return 1;
}

int main(int argc, char **argv)
{
    struct contract parsed;
    int exec_error_pipe[2] = {-1, -1};
    struct child_failure child_failure = {0, 0};
    int handshake;
    pid_t broker_pid;

    if (!parse_contract(argc, argv, &parsed)) {
        report_stderr("contract", EINVAL);
        return 64;
    }
    if (validate_descriptors() != 0) {
        int saved_errno = errno;
        report_stderr("descriptors", saved_errno);
        return 65;
    }
    if (validate_pass_descriptors(&parsed) != 0) {
        int saved_errno = errno;
        report_stderr("pass_fds", saved_errno);
        return 66;
    }
    if (set_sigpipe(SIG_IGN) != 0) {
        int saved_errno = errno;
        (void)report_record("signal", 0, saved_errno);
        return 67;
    }
    if (mark_unclassified_cloexec() != 0) {
        int saved_errno = errno;
        (void)report_record("fd_cloexec", 0, saved_errno);
        return 68;
    }
    if (pipe2(exec_error_pipe, O_CLOEXEC) != 0) {
        int saved_errno = errno;
        (void)report_record("exec_pipe", 0, saved_errno);
        return 69;
    }

    broker_pid = fork();
    if (broker_pid < 0) {
        int saved_errno = errno;
        close(exec_error_pipe[0]);
        close(exec_error_pipe[1]);
        (void)report_record("fork", 0, saved_errno);
        return 70;
    }
    if (broker_pid == 0) {
        struct child_failure failure;

        close(exec_error_pipe[0]);
        if (partition_branch(
                parsed.worker_pass_fds,
                parsed.worker_passc,
                parsed.broker_pass_fds,
                parsed.broker_passc) != 0) {
            failure.stage = CHILD_FAILURE_PARTITION;
            failure.error_number = errno;
        } else if (set_sigpipe(SIG_DFL) != 0) {
            failure.stage = CHILD_FAILURE_EXEC;
            failure.error_number = errno;
        } else {
            execveat(
                BWRAP_FD,
                "",
                parsed.broker_argv,
                minimal_environment,
                AT_EMPTY_PATH);
            failure.stage = CHILD_FAILURE_EXEC;
            failure.error_number = errno;
        }
        (void)atomic_write(
            exec_error_pipe[1],
            &failure,
            sizeof(failure));
        close(exec_error_pipe[1]);
        _exit(120);
    }

    close(exec_error_pipe[1]);
    if (partition_branch(
            parsed.broker_pass_fds,
            parsed.broker_passc,
            parsed.worker_pass_fds,
            parsed.worker_passc) != 0) {
        int saved_errno = errno;
        close(exec_error_pipe[0]);
        kill_and_reap(broker_pid);
        (void)report_record("worker_fds", 0, saved_errno);
        return 71;
    }
    handshake = read_child_failure(exec_error_pipe[0], &child_failure);
    close(exec_error_pipe[0]);
    if (handshake != 0) {
        int saved_errno = handshake < 0 ? EIO : child_failure.error_number;
        const char *stage = child_failure.stage == CHILD_FAILURE_PARTITION
            ? "broker_fds"
            : "broker_exec";

        if (handshake > 0
            && child_failure.stage != CHILD_FAILURE_PARTITION
            && child_failure.stage != CHILD_FAILURE_EXEC) {
            saved_errno = EIO;
            stage = "broker_exec";
        }
        (void)wait_exact(broker_pid);
        (void)report_record(stage, 0, saved_errno);
        return 72;
    }
    if (report_record(NULL, broker_pid, 0) != 0) {
        kill_and_reap(broker_pid);
        return 73;
    }
    if (set_sigpipe(SIG_DFL) != 0) {
        int saved_errno = errno;
        (void)report_record("worker_signal", 0, saved_errno);
        kill_and_reap(broker_pid);
        return 74;
    }
    execveat(
        BWRAP_FD,
        "",
        parsed.worker_argv,
        minimal_environment,
        AT_EMPTY_PATH);
    {
        int saved_errno = errno;
        (void)set_sigpipe(SIG_IGN);
        (void)report_record("worker_exec", 0, saved_errno);
        kill_and_reap(broker_pid);
    }
    return 75;
}
