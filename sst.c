// SPDX-License-Identifier: GPL-3.0-only
//
// Simple Sandboxer Tool (sst)
//
// A CLI tool that uses Linux Landlock API to sandbox programs.
// Similar in concept to bubblewrap(bwrap) but focused solely on Landlock.
//
// No root privileges required. This is a selling point of the Landlock API ;)
//
// Usage:
//   sst [options] -- <command> <arg1> <arg2> ... <argN>
//
// Check `README.md` for what options are available.
//
// (c) 2025 Mikko Juola
//

#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/landlock.h>

// I've ad-hoc added any #defines here when I hit a situation of
// linux/landlock.h not having the latest definitions.
#ifndef LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON
#define LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON 2
#endif

// How many rules we accept on command-line.
#define MAX_FS_RULES 1024
#define MAX_NET_RULES 1024

typedef struct sfs_rule {
    char* path;
    int is_directory;
    __u32 access;
} fs_rule;

typedef struct snet_rule {
    long port;
    int allow_incoming;
    int allow_outgoing;
} net_rule;

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(
        const struct landlock_ruleset_attr *const attr,
        const size_t size,
        const __u32 flags)
{
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(
        const int ruleset_fd,
        const enum landlock_rule_type rule_type,
        const void *const rule_attr,
        const __u32 flags)
{
    return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(
        const int ruleset_fd,
        const __u32 flags)
{
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

static void fatal_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "sst: error: ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);

    exit(1);
}

static void fatal_error_errno(const char *fmt, ...) {
    const int errno_captured = errno;

    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "sst: error: ");
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, ": %s\n", strerror(errno_captured));

    exit(1);
}

static void restrict_privileges_for_landlock(void) {
    // Landlock will fail if this is not set for the calling process.
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        fatal_error_errno("prctl(PR_SET_NO_NEW_PRIVS) failed");
    }
}

static int parse_port(const char *str, long *port_out) {
    const size_t len = strlen(str);

    if (len == 0 || len > 5) {
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        if (str[i] < '0' || str[i] > '9') {
            return -1;
        }
    }

    char *endptr = NULL;
    errno = 0;
    long port = strtol(str, &endptr, 10);

    if (endptr != str + len || errno != 0) {
        return -1;
    }

    if (port < 0 || port > 65535) {
        return -1;
    }

    *port_out = port;
    return 0;
}

static int is_regular_file(int fd) {
    struct stat sb;
    if (fstat(fd, &sb) != 0) {
        return -1;
    }
    return S_ISREG(sb.st_mode);
}

static int is_directory(int fd) {
    struct stat sb;
    if (fstat(fd, &sb) != 0) {
        return -1;
    }
    return S_ISDIR(sb.st_mode);
}

static const __u32 FULL_FS_ACCESS =
    LANDLOCK_ACCESS_FS_EXECUTE |
    LANDLOCK_ACCESS_FS_WRITE_FILE |
    LANDLOCK_ACCESS_FS_READ_FILE |
    LANDLOCK_ACCESS_FS_READ_DIR |
    LANDLOCK_ACCESS_FS_REMOVE_DIR |
    LANDLOCK_ACCESS_FS_REMOVE_FILE |
    LANDLOCK_ACCESS_FS_MAKE_CHAR |
    LANDLOCK_ACCESS_FS_MAKE_DIR |
    LANDLOCK_ACCESS_FS_MAKE_REG |
    LANDLOCK_ACCESS_FS_MAKE_SOCK |
    LANDLOCK_ACCESS_FS_MAKE_FIFO |
    LANDLOCK_ACCESS_FS_MAKE_BLOCK |
    LANDLOCK_ACCESS_FS_MAKE_SYM |
    LANDLOCK_ACCESS_FS_REFER |
    LANDLOCK_ACCESS_FS_TRUNCATE |
    LANDLOCK_ACCESS_FS_IOCTL_DEV;

static const __u32 READ_ACCESS =
    LANDLOCK_ACCESS_FS_READ_FILE |
    LANDLOCK_ACCESS_FS_READ_DIR;

static const __u32 READ_EXEC_ACCESS =
    LANDLOCK_ACCESS_FS_EXECUTE |
    LANDLOCK_ACCESS_FS_READ_FILE |
    LANDLOCK_ACCESS_FS_READ_DIR |
    LANDLOCK_ACCESS_FS_READ_DIR;

static const __u32 READ_WRITE_ACCESS =
    LANDLOCK_ACCESS_FS_READ_FILE |
    LANDLOCK_ACCESS_FS_READ_DIR |
    LANDLOCK_ACCESS_FS_WRITE_FILE |
    LANDLOCK_ACCESS_FS_TRUNCATE;

static const __u32 EXEC_WRITE_FILE_ACCESS =
    LANDLOCK_ACCESS_FS_EXECUTE |
    LANDLOCK_ACCESS_FS_READ_FILE |
    LANDLOCK_ACCESS_FS_READ_DIR |
    LANDLOCK_ACCESS_FS_WRITE_FILE |
    LANDLOCK_ACCESS_FS_TRUNCATE;

static void show_help(FILE* out) {
    // This is basically CHEATSHEET.md but slightly better formatted for
    // the terminal.
    fprintf(out, "sst - Simple Sandboxer Tool\n");
    fprintf(out, "(c) 2025 Mikko Juola\n");
    fprintf(out, "Licensed under GPL3\n");
    fprintf(out, "\n");
    fprintf(out, "`sst` runs a program with sandboxing applied through the use of Linux Landlock API\n");
    fprintf(out, "You enable sandboxing for a specific feature, and then you specify an allowlist of\n");
    fprintf(out, "operations you want to allow.\n");
    fprintf(out, "\n");
    fprintf(out, "Usage:\n");
    fprintf(out, "\n");
    fprintf(out, "    sst option1 option2 optionN -- command arg1 arg2 argN\n");
    fprintf(out, "\n");
    fprintf(out, "Enable sandboxing for filesystem/networking:\n");
    fprintf(out, "\n");
    fprintf(out, "    ENABLE_FILESYSTEM_SANDBOXING\n");
    fprintf(out, "    ENABLE_NETWORK_SANDBOXING\n");
    fprintf(out, "\n");
    fprintf(out, "Filesystem-related permissions:\n");
    fprintf(out, "\n");
    fprintf(out, "    FILE_READ:<filepath>\n");
    fprintf(out, "    FILE_EXEC:<filepath>\n");
    fprintf(out, "    FILE_WRITE:<filepath>\n");
    fprintf(out, "    FILE_EXEC_WRITE:<filepath>\n");
    fprintf(out, "    FILE_WRITE_EXEC:<filepath>\n");
    fprintf(out, "    PATH_BENEATH_READ:<dir>\n");
    fprintf(out, "    PATH_BENEATH_EXEC:<dir>\n");
    fprintf(out, "    PATH_BENEATH_WRITE:<dir>\n");
    fprintf(out, "    PATH_BENEATH_EXEC_WRITE:<dir>\n");
    fprintf(out, "    PATH_BENEATH_WRITE_EXEC:<dir>\n");
    fprintf(out, "\n");
    fprintf(out, "FILE_* must be used with regular files. PATH_BENEATH_* must be used with directories.\n");
    fprintf(out, "\n");
    fprintf(out, "Networking-related permissions:\n");
    fprintf(out, "\n");
    fprintf(out, "    ALLOW_INCOMING_TCP_PORT:<port>\n");
    fprintf(out, "    ALLOW_OUTGOING_TCP_PORT:<port>\n");
    fprintf(out, "\n");
    fprintf(out, "Example that stops TCP networking for a shell (and anything ran in it):\n");
    fprintf(out, "\n");
    fprintf(out, "    sst ENABLE_NETWORK_SANDBOXING -- bash\n");
    fprintf(out, "\n");
}

int main(int argc, char **argv, char *const *const envp) {
    restrict_privileges_for_landlock();

    // Is the user looking for help from their untimely demise? Or just
    // wanting to figure out wtf is 'sst' because they saw it in a shell
    // script somewhere. If yes, then print help, exit.
    if ((argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) ||
         argc == 1) {
        show_help(stdout);
        exit(0);
    }

    // Find the -- separator.
    int sep_idx = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            sep_idx = i;
            break;
        }
    }

    for (int i1 = 1; i1 < sep_idx; i1++) {
        if (strcmp(argv[i1], "--help") == 0 ||
            strcmp(argv[i1], "-h") == 0) {
            show_help(stderr);
            exit(1);
        }
    }

    if (sep_idx == -1) {
        fatal_error("missing '--' separator in arguments");
    }

    if (sep_idx == argc - 1) {
        fatal_error("no command specified after '--'");
    }

    int fs_sandboxing_enabled = 0;
    int net_sandboxing_enabled = 0;

    size_t fs_rule_count = 0;
    size_t net_rule_count = 0;

    fs_rule* fs_rules = NULL;
    net_rule* net_rules = NULL;

    // Look for the trigger words first; we are tolerant even if they are
    // specified last or multiple times etc.
    for (int i1 = 1; i1 < sep_idx; i1++) {
        const char *arg = argv[i1];

        if (strcmp(arg, "ENABLE_FILESYSTEM_SANDBOXING") == 0) {
            fs_sandboxing_enabled = 1;
            continue;
        }

        if (strcmp(arg, "ENABLE_NETWORK_SANDBOXING") == 0) {
            net_sandboxing_enabled = 1;
            continue;
        }
    }

    for (int i1 = 1; i1 < sep_idx; i1++) {
        const char *arg = argv[i1];
        const size_t arg_len = strlen(arg);

        // We already handled these in the previous for loop.
        if (strcmp(arg, "ENABLE_FILESYSTEM_SANDBOXING") == 0) {
            continue;
        }
        if (strcmp(arg, "ENABLE_NETWORK_SANDBOXING") == 0) {
            continue;
        }
        if (arg_len == 0) {
            fatal_error("There is an empty argument in argument list. strlen(argv[%d]) == 0", i1);
        }

        /****
         * FILESYSTEM
         ****/

        // TODO: a lot of repeated code here. The parts that vary are:
        // the option name and its length (e.g. "FILE_READ:", 10) and
        // what's put into the fs_rules[fs_rule_count].
        if (strncmp(arg, "FILE_READ:", 10) == 0) {
            if (!fs_sandboxing_enabled) {
                fatal_error("FILE_READ requires ENABLE_FILESYSTEM_SANDBOXING");
            }
            const char *path = arg + 10;
            if (strlen(path) == 0) {
                fatal_error("FILE_READ: missing path");
            }
            if (fs_rule_count >= MAX_FS_RULES) {
                fatal_error("too many filesystem rules");
            }
            const size_t realloc_sz = sizeof(fs_rule) * (fs_rule_count+1);
            fs_rules = realloc(fs_rules, realloc_sz);
            if (!fs_rules) {
                fatal_error_errno("realloc(..., %zu) failed.", realloc_sz);
            }
            fs_rules[fs_rule_count].path = strdup(path);
            if (!fs_rules[fs_rule_count].path) {
                fatal_error_errno("strdup(...) failed.");
            }
            fs_rules[fs_rule_count].is_directory = 0;
            fs_rules[fs_rule_count].access = READ_ACCESS;
            fs_rule_count++;
            continue;
        }

        if (strncmp(arg, "FILE_EXEC:", 10) == 0) {
            if (!fs_sandboxing_enabled) {
                fatal_error("FILE_EXEC requires ENABLE_FILESYSTEM_SANDBOXING");
            }
            const char *path = arg + 10;
            if (strlen(path) == 0) {
                fatal_error("FILE_EXEC: missing path");
            }
            if (fs_rule_count >= MAX_FS_RULES) {
                fatal_error("too many filesystem rules");
            }
            const size_t realloc_sz = sizeof(fs_rule) * (fs_rule_count+1);
            fs_rules = realloc(fs_rules, realloc_sz);
            if (!fs_rules) {
                fatal_error_errno("realloc(..., %zu) failed.", realloc_sz);
            }

            fs_rules[fs_rule_count].path = strdup(path);
            if (!fs_rules[fs_rule_count].path) {
                fatal_error_errno("strdup(...) failed.");
            }
            fs_rules[fs_rule_count].is_directory = 0;
            fs_rules[fs_rule_count].access = READ_EXEC_ACCESS;
            fs_rule_count++;
            continue;
        }

        if (strncmp(arg, "FILE_WRITE:", 11) == 0) {
            if (!fs_sandboxing_enabled) {
                fatal_error("FILE_WRITE requires ENABLE_FILESYSTEM_SANDBOXING");
            }
            const char *path = arg + 11;
            if (strlen(path) == 0) {
                fatal_error("FILE_WRITE: missing path");
            }
            if (fs_rule_count >= MAX_FS_RULES) {
                fatal_error("too many filesystem rules");
            }
            const size_t realloc_sz = sizeof(fs_rule) * (fs_rule_count+1);
            fs_rules = realloc(fs_rules, realloc_sz);
            if (!fs_rules) {
                fatal_error_errno("realloc(..., %zu) failed.", realloc_sz);
            }

            fs_rules[fs_rule_count].path = strdup(path);
            if (!fs_rules[fs_rule_count].path) {
                fatal_error_errno("strdup(...) failed.");
            }
            fs_rules[fs_rule_count].is_directory = 0;
            fs_rules[fs_rule_count].access = READ_WRITE_ACCESS;
            fs_rule_count++;
            continue;
        }

        if (strncmp(arg, "FILE_EXEC_WRITE:", 16) == 0 ||
            strncmp(arg, "FILE_WRITE_EXEC:", 16) == 0) {
            if (!fs_sandboxing_enabled) {
                fatal_error("FILE_EXEC_WRITE requires ENABLE_FILESYSTEM_SANDBOXING");
            }
            const char *path = arg + 16;
            if (strlen(path) == 0) {
                fatal_error("FILE_EXEC_WRITE: missing path");
            }
            if (fs_rule_count >= MAX_FS_RULES) {
                fatal_error("too many filesystem rules");
            }
            const size_t realloc_sz = sizeof(fs_rule) * (fs_rule_count+1);
            fs_rules = realloc(fs_rules, realloc_sz);
            if (!fs_rules) {
                fatal_error_errno("realloc(..., %zu) failed.", realloc_sz);
            }

            fs_rules[fs_rule_count].path = strdup(path);
            if (!fs_rules[fs_rule_count].path) {
                fatal_error_errno("strdup(...) failed.");
            }
            fs_rules[fs_rule_count].is_directory = 0;
            fs_rules[fs_rule_count].access = EXEC_WRITE_FILE_ACCESS;
            fs_rule_count++;
            continue;
        }

        if (strncmp(arg, "PATH_BENEATH_READ:", 18) == 0) {
            if (!fs_sandboxing_enabled) {
                fatal_error("PATH_BENEATH_READ requires ENABLE_FILESYSTEM_SANDBOXING");
            }
            const char *path = arg + 18;
            if (strlen(path) == 0) {
                fatal_error("PATH_BENEATH_READ: missing path");
            }
            if (fs_rule_count >= MAX_FS_RULES) {
                fatal_error("too many filesystem rules");
            }
            const size_t realloc_sz = sizeof(fs_rule) * (fs_rule_count+1);
            fs_rules = realloc(fs_rules, realloc_sz);
            if (!fs_rules) {
                fatal_error_errno("realloc(..., %zu) failed.", realloc_sz);
            }

            fs_rules[fs_rule_count].path = strdup(path);
            if (!fs_rules[fs_rule_count].path) {
                fatal_error_errno("strdup(...) failed.");
            }
            fs_rules[fs_rule_count].is_directory = 1;
            fs_rules[fs_rule_count].access = READ_ACCESS;
            fs_rule_count++;
            continue;
        }

        if (strncmp(arg, "PATH_BENEATH_EXEC:", 18) == 0) {
            if (!fs_sandboxing_enabled) {
                fatal_error("PATH_BENEATH_EXEC requires ENABLE_FILESYSTEM_SANDBOXING");
            }
            const char *path = arg + 18;
            if (strlen(path) == 0) {
                fatal_error("PATH_BENEATH_EXEC: missing path");
            }
            if (fs_rule_count >= MAX_FS_RULES) {
                fatal_error("too many filesystem rules");
            }
            const size_t realloc_sz = sizeof(fs_rule) * (fs_rule_count+1);
            fs_rules = realloc(fs_rules, realloc_sz);
            if (!fs_rules) {
                fatal_error_errno("realloc(..., %zu) failed.", realloc_sz);
            }

            fs_rules[fs_rule_count].path = strdup(path);
            if (!fs_rules[fs_rule_count].path) {
                fatal_error_errno("strdup(...) failed.");
            }
            fs_rules[fs_rule_count].is_directory = 1;
            fs_rules[fs_rule_count].access = READ_EXEC_ACCESS;
            fs_rule_count++;
            continue;
        }

        if (strncmp(arg, "PATH_BENEATH_WRITE:", 19) == 0) {
            if (!fs_sandboxing_enabled) {
                fatal_error("PATH_BENEATH_WRITE requires ENABLE_FILESYSTEM_SANDBOXING");
            }
            const char *path = arg + 19;
            if (strlen(path) == 0) {
                fatal_error("PATH_BENEATH_WRITE: missing path");
            }
            if (fs_rule_count >= MAX_FS_RULES) {
                fatal_error("too many filesystem rules");
            }
            const size_t realloc_sz = sizeof(fs_rule) * (fs_rule_count+1);
            fs_rules = realloc(fs_rules, realloc_sz);
            if (!fs_rules) {
                fatal_error_errno("realloc(..., %zu) failed.", realloc_sz);
            }

            fs_rules[fs_rule_count].path = strdup(path);
            if (!fs_rules[fs_rule_count].path) {
                fatal_error_errno("strdup(...) failed.");
            }
            fs_rules[fs_rule_count].is_directory = 1;
            fs_rules[fs_rule_count].access = READ_WRITE_ACCESS;
            fs_rule_count++;
            continue;
        }

        if (strncmp(arg, "PATH_BENEATH_EXEC_WRITE:", 24) == 0 ||
            strncmp(arg, "PATH_BENEATH_WRITE_EXEC:", 24) == 0) {
            if (!fs_sandboxing_enabled) {
                fatal_error("PATH_BENEATH_EXEC_WRITE requires ENABLE_FILESYSTEM_SANDBOXING");
            }
            const char *path = arg + 24;
            if (strlen(path) == 0) {
                fatal_error("PATH_BENEATH_EXEC_WRITE: missing path");
            }
            if (fs_rule_count >= MAX_FS_RULES) {
                fatal_error("too many filesystem rules");
            }
            const size_t realloc_sz = sizeof(fs_rule) * (fs_rule_count+1);
            fs_rules = realloc(fs_rules, realloc_sz);
            if (!fs_rules) {
                fatal_error_errno("realloc(..., %zu) failed.", realloc_sz);
            }
            fs_rules[fs_rule_count].path = strdup(path);
            if (!fs_rules[fs_rule_count].path) {
                fatal_error_errno("strdup(...) failed.");
            }

            fs_rules[fs_rule_count].is_directory = 1;
            fs_rules[fs_rule_count].access = EXEC_WRITE_FILE_ACCESS;
            fs_rule_count++;
            continue;
        }

        /****
         * NETWORKING
         ****/

        if (strncmp(arg, "ALLOW_INCOMING_TCP_PORT:", 24) == 0) {
            if (!net_sandboxing_enabled) {
                fatal_error("ALLOW_INCOMING_TCP_PORT requires ENABLE_NETWORK_SANDBOXING");
            }
            const char *port_str = arg + 24;
            long port;
            if (parse_port(port_str, &port) != 0) {
                fatal_error("ALLOW_INCOMING_TCP_PORT: invalid port '%s'", port_str);
            }
            if (net_rule_count >= MAX_NET_RULES) {
                fatal_error("too many network rules");
            }
            const size_t realloc_sz = sizeof(net_rule) * (net_rule_count+1);
            net_rules = realloc(net_rules, realloc_sz);
            if (!net_rules) {
                fatal_error_errno("realloc(..., %zu) failed.", realloc_sz);
            }
            net_rules[net_rule_count].port = port;
            net_rules[net_rule_count].allow_incoming = 1;
            net_rules[net_rule_count].allow_outgoing = 0;
            net_rule_count++;
            continue;
        }

        if (strncmp(arg, "ALLOW_OUTGOING_TCP_PORT:", 24) == 0) {
            if (!net_sandboxing_enabled) {
                fatal_error("ALLOW_OUTGOING_TCP_PORT requires ENABLE_NETWORK_SANDBOXING");
            }
            const char *port_str = arg + 24;
            long port;
            if (parse_port(port_str, &port) != 0) {
                fatal_error("ALLOW_OUTGOING_TCP_PORT: invalid port '%s'", port_str);
            }
            if (net_rule_count >= MAX_NET_RULES) {
                fatal_error("too many network rules");
            }
            const size_t realloc_sz = sizeof(net_rule) * (net_rule_count+1);
            net_rules = realloc(net_rules, realloc_sz);
            if (!net_rules) {
                fatal_error_errno("realloc(..., %zu) failed.", realloc_sz);
            }
            net_rules[net_rule_count].port = port;
            net_rules[net_rule_count].allow_incoming = 0;
            net_rules[net_rule_count].allow_outgoing = 1;
            net_rule_count++;
            continue;
        }

        fatal_error("unrecognized option: %s", arg);
    }

    // Fail if no sandboxing has been specified.
    // Wondering: technically we should just exec() the child to stay
    // consistent; maybe the command line to this tool is programmatically
    // generated. But I thought misusing `sst` is a more likely scenario.
    // This might be something to address later...maybe an option that says
    // `MIGHT_BE_EMPTY` (and can be specified any number of times) that
    // tells `sst` to accept no sandbox rules given.
    if (!fs_sandboxing_enabled && !net_sandboxing_enabled) {
        fatal_error("no sandboxing options given");
    }

    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        const int err = errno;
        if (err == ENOSYS) {
            fatal_error("Landlock is not supported by the kernel (ENOSYS)");
        } else if (err == EOPNOTSUPP) {
            fatal_error("Landlock is disabled in the kernel (EOPNOTSUPP)");
        } else {
            fatal_error_errno("landlock_create_ruleset failed");
        }
    }

    if (abi < 4) {
        fatal_error("Landlock ABI version %d is too old; version 4 or later required for this tool", abi);
    }

    struct landlock_ruleset_attr attr = {0};

    if (fs_sandboxing_enabled) {
        attr.handled_access_fs = FULL_FS_ACCESS;
    }

    if (net_sandboxing_enabled) {
        attr.handled_access_net =
            LANDLOCK_ACCESS_NET_BIND_TCP |
            LANDLOCK_ACCESS_NET_CONNECT_TCP;
    }

    // This flag makes noise when a restricted program attempts an
    // operation that Landlock blocks.
    //
    // Wondering if might need to get rid of this (or rather make it
    // configurable) if there are going to be spammy programs that push on
    // the limits.
    __u32 restrict_flags = LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;

    switch (abi) {
        case 4:
            attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
            __attribute__((fallthrough));
        case 5:
            __attribute__((fallthrough));
        case 6:
            restrict_flags &= ~LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;
            __attribute__((fallthrough));
        case 7:
            break;
        // I've heard rumors that ABI version 8 has UDP blocking...waiting
        // for it dammit.
        default:
            fprintf(stderr, "sst: warning: Landlock ABI version %d is newer than this tool was designed for. Some restrictions may not work as expected.\n", abi);
            break;
    }

    const int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        fatal_error_errno("failed to create Landlock ruleset");
    }

    for (size_t i = 0; i < fs_rule_count; i++) {
        const char *path = fs_rules[i].path;

        int fd;
        if (fs_rules[i].is_directory) {
            fd = open(path, O_PATH | O_CLOEXEC);
            const int is_dir = is_directory(fd);
            if (is_dir < 0) {
                fatal_error_errno("Cannot invoke fstat on '%s'", path);
            } else if (!is_dir) {
                fatal_error("PATH_BENEATH_*: '%s' is not a directory", path);
            }
        } else {
            fd = open(path, O_RDWR | O_CLOEXEC);
            const int is_reg = is_regular_file(fd);
            if (is_reg < 0) {
                fatal_error_errno("Cannot invoke fstat on '%s'", path);
            } else if (!is_reg) {
                fatal_error("FILE_*: '%s' is not a regular file", path);
            }
        }

        if (fd < 0) {
            fatal_error_errno("cannot open '%s' for sandboxing", path);
        }

        struct landlock_path_beneath_attr path_attr = {
            .parent_fd = fd,
            .allowed_access = fs_rules[i].access
        };

        if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0)) {
            fatal_error_errno("failed to add filesystem rule");
        }

        close(fd);
    }

    for (size_t i = 0; i < net_rule_count; i++) {
        struct landlock_net_port_attr port_attr = {
            .port = (unsigned int)net_rules[i].port,
            .allowed_access = 0
        };

        if (net_rules[i].allow_incoming) {
            port_attr.allowed_access |= LANDLOCK_ACCESS_NET_BIND_TCP;
        }
        if (net_rules[i].allow_outgoing) {
            port_attr.allowed_access |= LANDLOCK_ACCESS_NET_CONNECT_TCP;
        }

        if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &port_attr, 0)) {
            fatal_error_errno("failed to add network rule");
        }
    }

    if (landlock_restrict_self(ruleset_fd, restrict_flags)) {
        fatal_error_errno("failed to apply Landlock ruleset");
    }

    close(ruleset_fd);

    const char *command = argv[sep_idx + 1];
    char *const *command_args = &argv[sep_idx + 1];

    execvpe(command, command_args, envp);

    fatal_error_errno("execvpe failed");
}
