/*
 * JStack Beta.1 Linux isolation canary.
 *
 * This source is compiled into every qualified task image. The final binary
 * digest is bound in that task's toolVersions and checked before a model is
 * allowed to start. A zero exit code means every negative/positive boundary
 * below behaved as expected; it does not authorize execution by itself.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CANARY_VERSION "jstack-proof-canary-v1"

static int failure(const char *message) {
    fprintf(stderr, "canary failure: %s\n", message);
    return 1;
}

static int status_value_is(const char *name, const char *expected) {
    FILE *handle = fopen("/proc/self/status", "r");
    char line[512];
    size_t name_length = strlen(name);
    int match = 0;
    if (handle == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), handle) != NULL) {
        if (strncmp(line, name, name_length) == 0 && line[name_length] == ':') {
            char *value = line + name_length + 1;
            while (*value == ' ' || *value == '\t') {
                value++;
            }
            value[strcspn(value, "\r\n")] = '\0';
            match = strcmp(value, expected) == 0;
            break;
        }
    }
    fclose(handle);
    return match;
}

static int connect_ipv4(const char *address, unsigned short port) {
    struct sockaddr_in target;
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    int result;
    if (descriptor < 0) {
        return 0;
    }
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    if (inet_pton(AF_INET, address, &target.sin_addr) != 1) {
        close(descriptor);
        return 0;
    }
    result = connect(descriptor, (struct sockaddr *)&target, sizeof(target));
    close(descriptor);
    return result == 0;
}

static int connect_ipv6(const char *address, unsigned short port) {
    struct sockaddr_in6 target;
    int descriptor = socket(AF_INET6, SOCK_STREAM, 0);
    int result;
    if (descriptor < 0) {
        return 0;
    }
    memset(&target, 0, sizeof(target));
    target.sin6_family = AF_INET6;
    target.sin6_port = htons(port);
    if (inet_pton(AF_INET6, address, &target.sin6_addr) != 1) {
        close(descriptor);
        return 0;
    }
    result = connect(descriptor, (struct sockaddr *)&target, sizeof(target));
    close(descriptor);
    return result == 0;
}

static int dns_resolves(void) {
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    int status;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    status = getaddrinfo("jstack-canary.invalid", "443", &hints, &result);
    if (result != NULL) {
        freeaddrinfo(result);
    }
    return status == 0;
}

static int unexpected_path(const char *path) {
    struct stat value;
    return lstat(path, &value) == 0;
}

int main(void) {
    int descriptor;
    const char *workspace_probe = "/workspace/.jstack-isolation-canary";

    if (getuid() == 0 || getgid() == 0) {
        return failure("process is running as root");
    }
    if (!status_value_is("CapEff", "0000000000000000")) {
        return failure("effective Linux capabilities are not empty");
    }
    if (!status_value_is("NoNewPrivs", "1")) {
        return failure("no-new-privileges is not active");
    }

    errno = 0;
    descriptor = open("/.jstack-root-write-must-fail", O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (descriptor >= 0) {
        close(descriptor);
        unlink("/.jstack-root-write-must-fail");
        return failure("root filesystem is writable");
    }
    descriptor = open(workspace_probe, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (descriptor < 0) {
        return failure("bounded workspace is not writable");
    }
    if (write(descriptor, CANARY_VERSION, strlen(CANARY_VERSION)) < 0) {
        close(descriptor);
        unlink(workspace_probe);
        return failure("bounded workspace write failed");
    }
    close(descriptor);
    if (unlink(workspace_probe) != 0) {
        return failure("bounded workspace cleanup failed");
    }

    if (unexpected_path("/workspace/.jstack-holdout-sentinel") ||
        unexpected_path("/workspace/.jstack-host-secret-sentinel") ||
        unexpected_path("/host") || unexpected_path("/run/host-services")) {
        return failure("holdout or host sentinel is visible");
    }
    if (dns_resolves()) {
        return failure("DNS resolution is available");
    }
    if (connect_ipv4("1.1.1.1", 53) || connect_ipv4("169.254.169.254", 80) ||
        connect_ipv4("127.0.0.1", 1) ||
        connect_ipv6("2606:4700:4700::1111", 53) || connect_ipv6("::1", 1)) {
        return failure("IPv4, IPv6, loopback, or metadata connectivity is available");
    }

    printf("%s: pass\n", CANARY_VERSION);
    return 0;
}
