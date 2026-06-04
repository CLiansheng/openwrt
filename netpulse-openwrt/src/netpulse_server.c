#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(NETPULSE_NO_PCAP) && !defined(NETPULSE_DYNAMIC_PCAP)
#include <pcap.h>
#endif

#ifdef NETPULSE_DYNAMIC_PCAP
#include <sys/time.h>

#define PCAP_ERRBUF_SIZE 256
#define PCAP_ERROR -1

typedef unsigned int bpf_u_int32;
typedef struct pcap pcap_t;
typedef unsigned char u_char;

struct pcap_pkthdr {
    struct timeval ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};

typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

static void *g_pcap_lib = NULL;
static pcap_t *(*g_pcap_open_live)(const char *, int, int, int, char *) = NULL;
static int (*g_pcap_dispatch)(pcap_t *, int, pcap_handler, u_char *) = NULL;
static char *(*g_pcap_geterr)(pcap_t *) = NULL;
static void (*g_pcap_close)(pcap_t *) = NULL;

static bool load_pcap_runtime(char *errbuf, size_t cap) {
    if (g_pcap_lib) return true;

    const char *candidates[] = {"libpcap.so.1", "libpcap.so", NULL};
    for (int i = 0; candidates[i]; i++) {
        g_pcap_lib = dlopen(candidates[i], RTLD_NOW);
        if (g_pcap_lib) break;
    }
    if (!g_pcap_lib) {
        snprintf(errbuf, cap, "dlopen libpcap failed: %s", dlerror());
        return false;
    }

    g_pcap_open_live = (pcap_t *(*)(const char *, int, int, int, char *))dlsym(g_pcap_lib, "pcap_open_live");
    g_pcap_dispatch = (int (*)(pcap_t *, int, pcap_handler, u_char *))dlsym(g_pcap_lib, "pcap_dispatch");
    g_pcap_geterr = (char *(*)(pcap_t *))dlsym(g_pcap_lib, "pcap_geterr");
    g_pcap_close = (void (*)(pcap_t *))dlsym(g_pcap_lib, "pcap_close");

    if (!g_pcap_open_live || !g_pcap_dispatch || !g_pcap_geterr || !g_pcap_close) {
        snprintf(errbuf, cap, "dlsym libpcap failed: %s", dlerror());
        return false;
    }
    return true;
}

#define pcap_open_live g_pcap_open_live
#define pcap_dispatch g_pcap_dispatch
#define pcap_geterr g_pcap_geterr
#define pcap_close g_pcap_close
#endif

#define MAX_ENTRIES 512
#define WINDOW_SECONDS 40
#define RECV_BUFFER 16384
#define RESPONSE_BUFFER 131072

typedef struct {
    time_t second;
    unsigned long long rx_bytes;
    unsigned long long tx_bytes;
} traffic_bucket_t;

typedef struct {
    char ip[INET6_ADDRSTRLEN];
    unsigned long long rx_total;
    unsigned long long tx_total;
    unsigned long long peak_bps;
    traffic_bucket_t buckets[WINDOW_SECONDS];
    time_t last_seen;
} traffic_entry_t;

typedef struct {
    char interface_name[64];
    char web_root[256];
    char firewall_script[256];
    int listen_port;
} app_config_t;

static traffic_entry_t g_entries[MAX_ENTRIES];
static int g_entry_count = 0;
static pthread_mutex_t g_stats_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t g_running = 1;
static app_config_t g_config = {
    .interface_name = "br-lan",
    .web_root = "./web",
    .firewall_script = "./scripts/firewall.sh",
    .listen_port = 8080,
};

static void stop_server(int signo) {
    (void)signo;
    g_running = 0;
}

static void appendf(char *buf, size_t cap, size_t *len, const char *fmt, ...) {
    if (*len >= cap) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf + *len, cap - *len, fmt, args);
    va_end(args);

    if (n < 0) {
        return;
    }
    if ((size_t)n >= cap - *len) {
        *len = cap - 1;
    } else {
        *len += (size_t)n;
    }
}

static void json_escape(const char *src, char *dst, size_t cap) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 2 < cap; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            if (j + 2 >= cap) break;
            dst[j++] = '\\';
            dst[j++] = (char)c;
        } else if (c == '\n') {
            if (j + 2 >= cap) break;
            dst[j++] = '\\';
            dst[j++] = 'n';
        } else if (c == '\r') {
            if (j + 2 >= cap) break;
            dst[j++] = '\\';
            dst[j++] = 'r';
        } else if (c == '\t') {
            if (j + 2 >= cap) break;
            dst[j++] = '\\';
            dst[j++] = 't';
        } else if (c >= 32) {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
}

static int find_or_create_entry(const char *ip) {
    for (int i = 0; i < g_entry_count; i++) {
        if (strcmp(g_entries[i].ip, ip) == 0) {
            return i;
        }
    }

    if (g_entry_count >= MAX_ENTRIES) {
        return -1;
    }

    int idx = g_entry_count++;
    memset(&g_entries[idx], 0, sizeof(g_entries[idx]));
    snprintf(g_entries[idx].ip, sizeof(g_entries[idx].ip), "%s", ip);
    return idx;
}

static void update_entry(const char *ip, unsigned int bytes, bool rx) {
    time_t now = time(NULL);
    pthread_mutex_lock(&g_stats_lock);
    int idx = find_or_create_entry(ip);
    if (idx >= 0) {
        traffic_entry_t *entry = &g_entries[idx];
        int bucket_idx = (int)(now % WINDOW_SECONDS);
        if (entry->buckets[bucket_idx].second != now) {
            entry->buckets[bucket_idx].second = now;
            entry->buckets[bucket_idx].rx_bytes = 0;
            entry->buckets[bucket_idx].tx_bytes = 0;
        }

        if (rx) {
            entry->rx_total += bytes;
            entry->buckets[bucket_idx].rx_bytes += bytes;
        } else {
            entry->tx_total += bytes;
            entry->buckets[bucket_idx].tx_bytes += bytes;
        }

        unsigned long long current_bps =
            (entry->buckets[bucket_idx].rx_bytes + entry->buckets[bucket_idx].tx_bytes) * 8ULL;
        if (current_bps > entry->peak_bps) {
            entry->peak_bps = current_bps;
        }
        entry->last_seen = now;
    }
    pthread_mutex_unlock(&g_stats_lock);
}

#ifndef NETPULSE_NO_PCAP
static void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)user;
    if (header->caplen < sizeof(struct ether_header)) {
        return;
    }

    const struct ether_header *eth = (const struct ether_header *)packet;
    unsigned short ether_type = ntohs(eth->ether_type);
    const unsigned char *payload = packet + sizeof(struct ether_header);
    unsigned int payload_len = header->caplen - sizeof(struct ether_header);
    char src[INET6_ADDRSTRLEN] = {0};
    char dst[INET6_ADDRSTRLEN] = {0};

    if (ether_type == ETHERTYPE_IP) {
        if (payload_len < sizeof(struct ip)) return;
        const struct ip *ip4 = (const struct ip *)payload;
        inet_ntop(AF_INET, &ip4->ip_src, src, sizeof(src));
        inet_ntop(AF_INET, &ip4->ip_dst, dst, sizeof(dst));
    } else if (ether_type == ETHERTYPE_IPV6) {
        if (payload_len < sizeof(struct ip6_hdr)) return;
        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)payload;
        inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));
    } else {
        return;
    }

    if (src[0]) update_entry(src, header->len, false);
    if (dst[0]) update_entry(dst, header->len, true);
}

static void *capture_thread(void *arg) {
    const char *device = (const char *)arg;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
#ifdef NETPULSE_DYNAMIC_PCAP
    if (!load_pcap_runtime(errbuf, sizeof(errbuf))) {
        fprintf(stderr, "%s\n", errbuf);
        return NULL;
    }
#endif
    pcap_t *handle = pcap_open_live(device, 65535, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", device, errbuf);
        return NULL;
    }

    while (g_running) {
        int rc = pcap_dispatch(handle, 32, packet_handler, NULL);
        if (rc == PCAP_ERROR) {
            fprintf(stderr, "pcap_dispatch failed: %s\n", pcap_geterr(handle));
            break;
        }
    }

    pcap_close(handle);
    return NULL;
}
#else
static void *capture_thread(void *arg) {
    const char *device = (const char *)arg;
    fprintf(stderr, "NETPULSE_NO_PCAP enabled; using simulated traffic for interface %s\n", device);
    while (g_running) {
        update_entry("192.168.1.10", 1200, false);
        update_entry("192.168.1.1", 900, true);
        update_entry("223.5.5.5", 1800, true);
        sleep(1);
    }
    return NULL;
}
#endif

static unsigned long long avg_bps_for(const traffic_entry_t *entry, int seconds, time_t now) {
    unsigned long long bytes = 0;
    for (int i = 0; i < WINDOW_SECONDS; i++) {
        if (entry->buckets[i].second > 0 && now - entry->buckets[i].second < seconds) {
            bytes += entry->buckets[i].rx_bytes + entry->buckets[i].tx_bytes;
        }
    }
    return (bytes * 8ULL) / (unsigned long long)seconds;
}

static void build_traffic_json(char *out, size_t cap) {
    size_t len = 0;
    time_t now = time(NULL);
    appendf(out, cap, &len, "{\"interface\":\"%s\",\"timestamp\":%lld,\"items\":[",
            g_config.interface_name, (long long)now);

    pthread_mutex_lock(&g_stats_lock);
    for (int i = 0; i < g_entry_count; i++) {
        traffic_entry_t snapshot = g_entries[i];
        if (i > 0) appendf(out, cap, &len, ",");
        appendf(out, cap, &len,
                "{\"ip\":\"%s\",\"rxBytes\":%llu,\"txBytes\":%llu,\"totalBytes\":%llu,"
                "\"peakBps\":%llu,\"avg2sBps\":%llu,\"avg10sBps\":%llu,\"avg40sBps\":%llu,"
                "\"lastSeen\":%lld}",
                snapshot.ip,
                snapshot.rx_total,
                snapshot.tx_total,
                snapshot.rx_total + snapshot.tx_total,
                snapshot.peak_bps,
                avg_bps_for(&snapshot, 2, now),
                avg_bps_for(&snapshot, 10, now),
                avg_bps_for(&snapshot, 40, now),
                (long long)snapshot.last_seen);
    }
    pthread_mutex_unlock(&g_stats_lock);

    appendf(out, cap, &len, "]}");
}

static const char *content_type_for(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    if (strcmp(ext, ".html") == 0) return "text/html; charset=utf-8";
    if (strcmp(ext, ".css") == 0) return "text/css; charset=utf-8";
    if (strcmp(ext, ".js") == 0) return "application/javascript; charset=utf-8";
    if (strcmp(ext, ".json") == 0) return "application/json; charset=utf-8";
    return "application/octet-stream";
}

static void send_response(int client, int status, const char *status_text, const char *content_type, const char *body) {
    char header[512];
    size_t body_len = body ? strlen(body) : 0;
    int n = snprintf(header, sizeof(header),
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "Access-Control-Allow-Origin: *\r\n"
                     "Access-Control-Allow-Headers: Content-Type\r\n"
                     "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                     "Connection: close\r\n\r\n",
                     status, status_text, content_type, body_len);
    send(client, header, (size_t)n, 0);
    if (body_len > 0) {
        send(client, body, body_len, 0);
    }
}

static bool read_file(const char *path, char **data, size_t *size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    if (len < 0 || len > 1024 * 1024) {
        fclose(fp);
        return false;
    }
    rewind(fp);
    char *buf = (char *)calloc((size_t)len + 1, 1);
    if (!buf) {
        fclose(fp);
        return false;
    }
    size_t n = fread(buf, 1, (size_t)len, fp);
    fclose(fp);
    buf[n] = '\0';
    *data = buf;
    *size = n;
    return true;
}

static void serve_static(int client, const char *url_path) {
    char file_path[512];
    const char *name = url_path;
    if (strcmp(url_path, "/") == 0) {
        name = "/index.html";
    }
    if (strstr(name, "..")) {
        send_response(client, 400, "Bad Request", "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"invalid path\"}");
        return;
    }
    snprintf(file_path, sizeof(file_path), "%s%s", g_config.web_root, name);

    char *data = NULL;
    size_t size = 0;
    if (!read_file(file_path, &data, &size)) {
        send_response(client, 404, "Not Found", "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"not found\"}");
        return;
    }

    (void)size;
    send_response(client, 200, "OK", content_type_for(file_path), data);
    free(data);
}

static bool json_get_string(const char *json, const char *key, char *out, size_t cap) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return false;
    p = strchr(p + strlen(pattern), ':');
    if (!p) return false;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return false;
    p++;

    size_t j = 0;
    while (*p && *p != '"' && j + 1 < cap) {
        if (*p == '\\' && p[1]) p++;
        out[j++] = *p++;
    }
    out[j] = '\0';
    return true;
}

static bool is_allowed_word(const char *value, const char *const *allowed) {
    for (int i = 0; allowed[i]; i++) {
        if (strcmp(value, allowed[i]) == 0) return true;
    }
    return false;
}

static bool valid_ip_or_any(const char *value) {
    if (value[0] == '\0' || strcmp(value, "any") == 0) return true;

    char ip[80];
    snprintf(ip, sizeof(ip), "%s", value);
    char *slash = strchr(ip, '/');
    if (slash) {
        *slash = '\0';
        char *end = NULL;
        long prefix = strtol(slash + 1, &end, 10);
        if (!end || *end != '\0' || prefix < 0 || prefix > 32) return false;
    }

    struct in_addr a4;
    return inet_pton(AF_INET, ip, &a4) == 1;
}

static bool valid_port_or_empty(const char *value) {
    if (value[0] == '\0' || strcmp(value, "any") == 0) return true;
    char *end = NULL;
    long port = strtol(value, &end, 10);
    return end && *end == '\0' && port >= 1 && port <= 65535;
}

static int run_script_capture(char *const argv[], char *out, size_t cap) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        snprintf(out, cap, "pipe failed: %s", strerror(errno));
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        snprintf(out, cap, "fork failed: %s", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execv(argv[0], argv);
        dprintf(STDERR_FILENO, "execv failed: %s\n", strerror(errno));
        _exit(127);
    }

    close(pipefd[1]);
    size_t used = 0;
    while (used + 1 < cap) {
        ssize_t n = read(pipefd[0], out + used, cap - used - 1);
        if (n <= 0) break;
        used += (size_t)n;
    }
    out[used] = '\0';
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
}

static void reply_script_result(int client, int exit_code, const char *script_output) {
    char escaped[RESPONSE_BUFFER];
    char body[RESPONSE_BUFFER];
    size_t len = 0;
    json_escape(script_output, escaped, sizeof(escaped));
    appendf(body, sizeof(body), &len, "{\"ok\":%s,\"exitCode\":%d,\"output\":\"",
            exit_code == 0 ? "true" : "false", exit_code);
    appendf(body, sizeof(body), &len, "%s\"}", escaped);
    send_response(client, exit_code == 0 ? 200 : 500, exit_code == 0 ? "OK" : "Script Error",
                  "application/json; charset=utf-8", body);
}

static void handle_firewall_add(int client, const char *body) {
    static const char *const protocols[] = {"all", "tcp", "udp", "icmp", NULL};
    static const char *const actions[] = {"accept", "reject", "drop", NULL};
    char protocol[16] = "all";
    char src[80] = "any";
    char dst[80] = "any";
    char port[16] = "";
    char action[16] = "drop";

    json_get_string(body, "protocol", protocol, sizeof(protocol));
    json_get_string(body, "src", src, sizeof(src));
    json_get_string(body, "dst", dst, sizeof(dst));
    json_get_string(body, "port", port, sizeof(port));
    json_get_string(body, "action", action, sizeof(action));

    if (!is_allowed_word(protocol, protocols) || !is_allowed_word(action, actions) ||
        !valid_ip_or_any(src) || !valid_ip_or_any(dst) || !valid_port_or_empty(port)) {
        send_response(client, 400, "Bad Request", "application/json; charset=utf-8",
                      "{\"ok\":false,\"error\":\"invalid firewall parameters\"}");
        return;
    }

    if ((strcmp(protocol, "icmp") == 0 || strcmp(protocol, "all") == 0) && port[0] != '\0' && strcmp(port, "any") != 0) {
        send_response(client, 400, "Bad Request", "application/json; charset=utf-8",
                      "{\"ok\":false,\"error\":\"port is only supported for tcp or udp\"}");
        return;
    }

    char output[RESPONSE_BUFFER];
    char *argv[] = {g_config.firewall_script, "add", protocol, src, dst, port, action, NULL};
    int exit_code = run_script_capture(argv, output, sizeof(output));
    reply_script_result(client, exit_code, output);
}

static void handle_firewall_delete(int client, const char *body) {
    char id[32] = {0};
    json_get_string(body, "id", id, sizeof(id));
    for (size_t i = 0; id[i]; i++) {
        if (id[i] < '0' || id[i] > '9') {
            send_response(client, 400, "Bad Request", "application/json; charset=utf-8",
                          "{\"ok\":false,\"error\":\"invalid rule id\"}");
            return;
        }
    }
    if (id[0] == '\0') {
        send_response(client, 400, "Bad Request", "application/json; charset=utf-8",
                      "{\"ok\":false,\"error\":\"missing rule id\"}");
        return;
    }

    char output[RESPONSE_BUFFER];
    char *argv[] = {g_config.firewall_script, "delete", id, NULL};
    int exit_code = run_script_capture(argv, output, sizeof(output));
    reply_script_result(client, exit_code, output);
}

static void handle_firewall_command(int client, const char *command) {
    char output[RESPONSE_BUFFER];
    char *argv[] = {g_config.firewall_script, (char *)command, NULL};
    int exit_code = run_script_capture(argv, output, sizeof(output));
    reply_script_result(client, exit_code, output);
}

static const char *find_body(char *request) {
    char *body = strstr(request, "\r\n\r\n");
    if (!body) return "";
    return body + 4;
}

static void handle_client(int client) {
    char request[RECV_BUFFER];
    ssize_t n = recv(client, request, sizeof(request) - 1, 0);
    if (n <= 0) return;
    request[n] = '\0';

    char method[8] = {0};
    char path[256] = {0};
    sscanf(request, "%7s %255s", method, path);

    char *query = strchr(path, '?');
    if (query) *query = '\0';

    if (strcmp(method, "OPTIONS") == 0) {
        send_response(client, 200, "OK", "text/plain; charset=utf-8", "");
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/traffic") == 0) {
        char *body = (char *)calloc(RESPONSE_BUFFER, 1);
        if (!body) {
            send_response(client, 500, "Internal Error", "application/json; charset=utf-8", "{\"ok\":false}");
            return;
        }
        build_traffic_json(body, RESPONSE_BUFFER);
        send_response(client, 200, "OK", "application/json; charset=utf-8", body);
        free(body);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/firewall/list") == 0) {
        handle_firewall_command(client, "list");
    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/api/firewall/add") == 0) {
        handle_firewall_add(client, find_body(request));
    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/api/firewall/delete") == 0) {
        handle_firewall_delete(client, find_body(request));
    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/api/firewall/clear") == 0) {
        handle_firewall_command(client, "clear");
    } else if (strcmp(method, "GET") == 0) {
        serve_static(client, path);
    } else {
        send_response(client, 405, "Method Not Allowed", "application/json; charset=utf-8",
                      "{\"ok\":false,\"error\":\"method not allowed\"}");
    }
}

static int start_http_server(void) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int yes = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)g_config.listen_port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }
    if (listen(server_fd, 16) != 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("NetPulse server listening on http://0.0.0.0:%d\n", g_config.listen_port);
    printf("Capture interface: %s\n", g_config.interface_name);
    fflush(stdout);

    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        handle_client(client);
        close(client);
    }

    close(server_fd);
    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [-i interface] [-p port] [-w web_root] [-s firewall_script]\n"
            "Example: %s -i br-lan -p 8080\n",
            prog, prog);
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "i:p:w:s:h")) != -1) {
        switch (opt) {
            case 'i':
                snprintf(g_config.interface_name, sizeof(g_config.interface_name), "%s", optarg);
                break;
            case 'p':
                g_config.listen_port = atoi(optarg);
                break;
            case 'w':
                snprintf(g_config.web_root, sizeof(g_config.web_root), "%s", optarg);
                break;
            case 's':
                snprintf(g_config.firewall_script, sizeof(g_config.firewall_script), "%s", optarg);
                break;
            case 'h':
            default:
                usage(argv[0]);
                return opt == 'h' ? 0 : 1;
        }
    }

    signal(SIGINT, stop_server);
    signal(SIGTERM, stop_server);

    pthread_t tid;
    if (pthread_create(&tid, NULL, capture_thread, g_config.interface_name) != 0) {
        perror("pthread_create");
        return 1;
    }

    int rc = start_http_server();
    g_running = 0;
    pthread_join(tid, NULL);
    return rc;
}
