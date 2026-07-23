#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define MAX_ALERTS 500

/* ===========================
   ALERT STRUCTURE
   =========================== */

typedef struct {
    char process[128];
    char pid[16];
    char ip[128];
    char port[16];
    char protocol[16];
    char local_ip[128];
    char local_port[16];
    char risk[16];
} Alert;

Alert alerts[MAX_ALERTS];
int total_alerts = 0;

/* ===========================
   PROCESS WHITELIST
   =========================== */

const char *whitelist[] = {
    "firefox", "firefox-esr", "steam", "electron", "chrome", "chromium",
    "systemd", "NetworkManager", "thunderbird", "discord",
    "telegram-desktop", "signal-desktop", "spotify", "slack",
    "code", "code-oss", "opencode", "obsidian", "mysql", "postgres",
    NULL
};

/* ===========================
   DANGEROUS PORTS
   =========================== */

int is_dangerous_port(int port) {
    int dangerous[] = {
        4444, 1337, 9001, 31337, 5555, 6666, 6667,
        4443, 4445, 1234, 2345, 3456, 4567, 5678,
        10001, 10002, 20000, 30000
    };
    int n = sizeof(dangerous) / sizeof(dangerous[0]);
    for (int i = 0; i < n; i++) {
        if (port == dangerous[i]) return 1;
    }
    return 0;
}

/* ===========================
   STRING UTILITIES
   =========================== */

/* Remove newline/carriage return from string */
void strip_newline(char *str) {
    str[strcspn(str, "\n")] = 0;
    str[strcspn(str, "\r")] = 0;
}

/* Escape characters that break JSON output */
void sanitize_json(char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == '\"') str[i] = '\'';
        if (str[i] == '\\') str[i] = '/';
    }
}

/* ===========================
   TIMESTAMP
   =========================== */

void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", &tm_buf);
}

/* ===========================
   PRIVATE IP DETECTION
   =========================== */

int is_private_ip(const char *ip) {
    if (strncmp(ip, "192.168.", 8) == 0) return 1;
    if (strncmp(ip, "10.", 3) == 0) return 1;
    if (strncmp(ip, "172.", 4) == 0) {
        int second = atoi(ip + 4);
        if (second >= 16 && second <= 31) return 1;
    }
    if (strcmp(ip, "127.0.0.1") == 0) return 1;
    if (strcmp(ip, "::1") == 0) return 1;
    if (strstr(ip, "::ffff:192.168.") != NULL) return 1;
    return 0;
}

/* ===========================
   WHITELIST CHECK
   =========================== */

int in_whitelist(const char *process) {
    for (int i = 0; whitelist[i] != NULL; i++) {
        if (strcmp(process, whitelist[i]) == 0) return 1;
    }
    return 0;
}

/* ===========================
   RISK CLASSIFICATION
   =========================== */

void classify_risk(const char *process, const char *port,
                   const char *ip, char *result) {
    int port_num = atoi(port);
    int is_external = !is_private_ip(ip);
    int is_suspicious = 0;

    /* Check if process is a known suspicious tool */
    if (strcmp(process, "bash") == 0 || strcmp(process, "sh") == 0 ||
        strcmp(process, "nc") == 0 || strcmp(process, "netcat") == 0 ||
        strcmp(process, "python") == 0 || strcmp(process, "perl") == 0 ||
        strcmp(process, "ruby") == 0 || strcmp(process, "ncat") == 0 ||
        strcmp(process, "socat") == 0 || strcmp(process, "nmap") == 0) {
        is_suspicious = 1;
    }

    /* 1. Known dangerous port -> HIGH */
    if (is_dangerous_port(port_num)) {
        strncpy(result, "HIGH", 15);
        return;
    }

    /* 2. Suspicious process (shells, network tools) -> HIGH */
    if (is_suspicious) {
        strncpy(result, "HIGH", 15);
        return;
    }

    /* 3. Whitelisted process (browsers, system, etc.) -> LOW */
    if (in_whitelist(process)) {
        strncpy(result, "LOW", 15);
        return;
    }

    /* 4. Private IP + common port -> LOW */
    if (!is_external && (port_num == 80 || port_num == 443 ||
                         port_num == 53 || port_num == 22 ||
                         port_num == 3306 || port_num == 5432)) {
        strncpy(result, "LOW", 15);
        return;
    }

    /* 5. External IP + common port (web, DNS, SSH) -> MEDIUM */
    if (port_num == 80 || port_num == 443 ||
        port_num == 53 || port_num == 22) {
        strncpy(result, "MEDIUM", 15);
        return;
    }

    /* 6. Private IP + high port -> MEDIUM */
    if (!is_external) {
        strncpy(result, "MEDIUM", 15);
        return;
    }

    /* 7. External IP + high port -> HIGH */
    strncpy(result, "HIGH", 15);
}

/* ===========================
   JSON GENERATION
   =========================== */

void generate_json(void) {
    /* Write to absolute path relative to binary location */
    char json_path[512];
    ssize_t len = readlink("/proc/self/exe", json_path, sizeof(json_path) - 1);
    if (len == -1) {
        strncpy(json_path, "monitor_data.json", sizeof(json_path));
    } else {
        json_path[len] = '\0';
        /* Replace binary name with data file name */
        char *last_slash = strrchr(json_path, '/');
        if (last_slash) {
            *(last_slash + 1) = '\0';
            strncat(json_path, "monitor_data.json",
                    sizeof(json_path) - strlen(json_path) - 1);
        }
    }

    FILE *fp = fopen(json_path, "w");
    if (fp == NULL) return;

    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    int count_low = 0, count_medium = 0, count_high = 0;
    for (int i = 0; i < total_alerts; i++) {
        if (strcmp(alerts[i].risk, "LOW") == 0) count_low++;
        else if (strcmp(alerts[i].risk, "MEDIUM") == 0) count_medium++;
        else if (strcmp(alerts[i].risk, "HIGH") == 0) count_high++;
    }

    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    fprintf(fp, "{\n");
    fprintf(fp, "  \"metadata\": {\n");
    fprintf(fp, "    \"tool\": \"Puster 3.5\",\n");
    fprintf(fp, "    \"hostname\": \"%s\",\n", hostname);
    fprintf(fp, "    \"timestamp\": \"%s\"\n", timestamp);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"summary\": {\n");
    fprintf(fp, "    \"total_connections\": %d,\n", total_alerts);
    fprintf(fp, "    \"low\": %d,\n", count_low);
    fprintf(fp, "    \"medium\": %d,\n", count_medium);
    fprintf(fp, "    \"high\": %d\n", count_high);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"alerts\": [\n");

    for (int i = 0; i < total_alerts; i++) {
        sanitize_json(alerts[i].process);
        sanitize_json(alerts[i].ip);
        sanitize_json(alerts[i].port);
        sanitize_json(alerts[i].protocol);
        sanitize_json(alerts[i].local_ip);
        sanitize_json(alerts[i].local_port);
        sanitize_json(alerts[i].pid);

        fprintf(fp, "    {\n");
        fprintf(fp, "      \"process\": \"%s\",\n", alerts[i].process);
        fprintf(fp, "      \"pid\": \"%s\",\n", alerts[i].pid);
        fprintf(fp, "      \"protocol\": \"%s\",\n", alerts[i].protocol);
        fprintf(fp, "      \"remote_ip\": \"%s\",\n", alerts[i].ip);
        fprintf(fp, "      \"remote_port\": \"%s\",\n", alerts[i].port);
        fprintf(fp, "      \"local_ip\": \"%s\",\n", alerts[i].local_ip);
        fprintf(fp, "      \"local_port\": \"%s\",\n", alerts[i].local_port);
        fprintf(fp, "      \"risk\": \"%s\"\n", alerts[i].risk);

        if (i == total_alerts - 1)
            fprintf(fp, "    }\n");
        else
            fprintf(fp, "    },\n");
    }

    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    fclose(fp);
}

/* ===========================
   CONNECTION DETECTION
   =========================== */

void detect_remote_connections(void) {
    total_alerts = 0;

    /* Scan TCP/UDP established/active connections */
    FILE *fp = popen("ss -tunp 2>/dev/null | tail -n +2", "r");
    if (fp == NULL) return;

    char *line = NULL;
    size_t line_len = 0;

    while (getline(&line, &line_len, fp) != -1 && total_alerts < MAX_ALERTS) {
        if (strstr(line, "LISTEN") != NULL) continue;

        Alert *a = &alerts[total_alerts];
        memset(a, 0, sizeof(Alert));

        /*
         * ss format: netid state recv send local:port remote:port [users]
         * Example: tcp ESTAB 0 0 192.168.1.2:37450 151.101.53.91:443 users:(("firefox",...))
         */
        char netid[16], state[16], recv_s[16], send_s[16];
        char local_s[128], remote_s[128], users[512];

        int n = sscanf(line, "%15s %15s %15s %15s %127s %127s %511[^\n]",
                       netid, state, recv_s, send_s, local_s, remote_s, users);

        if (n < 6) continue;

        snprintf(a->protocol, sizeof(a->protocol), "%s", netid);

        /* Parse remote address */
        char *rdp = strrchr(remote_s, ':');
        if (rdp != NULL) {
            *rdp = '\0';
            snprintf(a->ip, sizeof(a->ip), "%s", remote_s);
            snprintf(a->port, sizeof(a->port), "%s", rdp + 1);
        } else {
            snprintf(a->ip, sizeof(a->ip), "%s", remote_s);
            snprintf(a->port, sizeof(a->port), "?");
        }

        /* Parse local address */
        char *ldp = strrchr(local_s, ':');
        if (ldp != NULL) {
            *ldp = '\0';
            snprintf(a->local_ip, sizeof(a->local_ip), "%s", local_s);
            snprintf(a->local_port, sizeof(a->local_port), "%s", ldp + 1);
        }

        /* Extract process name and PID from users field */
        if (n >= 7 && strlen(users) > 0) {
            char *proc_start = strstr(users, "users:((");
            if (proc_start != NULL) {
                proc_start += 8; /* skip "users:((" */
                if (*proc_start == '\"') proc_start++; /* skip opening quote */
                char *proc_end = strchr(proc_start, '\"'); /* find closing quote */
                if (proc_end != NULL) {
                    int plen = (int)(proc_end - proc_start);
                    if (plen > 127) plen = 127;
                    snprintf(a->process, sizeof(a->process), "%.*s", plen, proc_start);
                }
            }
            char *pid_tag = strstr(users, "pid=");
            if (pid_tag != NULL) {
                pid_tag += 4;
                int pi = 0;
                while (pid_tag[pi] >= '0' && pid_tag[pi] <= '9' && pi < 15) {
                    a->pid[pi] = pid_tag[pi];
                    pi++;
                }
                a->pid[pi] = '\0';
            }
        }

        /* Clean %scope_id from IPv6 addresses */
        char *pct = strchr(a->ip, '%');
        if (pct != NULL) *pct = '\0';
        pct = strchr(a->local_ip, '%');
        if (pct != NULL) *pct = '\0';

        if (strlen(a->process) == 0)
            snprintf(a->process, sizeof(a->process), "unknown");

        if (strlen(a->pid) == 0)
            snprintf(a->pid, sizeof(a->pid), "-");

        /* Skip connections without valid remote IP (bound sockets, etc.) */
        if (strcmp(a->ip, "0") == 0 || strcmp(a->ip, "0.0.0.0") == 0 ||
            strcmp(a->ip, "::") == 0 || strlen(a->ip) == 0 ||
            strcmp(a->port, "?") == 0) {
            continue;
        }

        /* Local loopback (::1) is always LOW */
        if (strcmp(a->ip, "::1") == 0) {
            strncpy(a->risk, "LOW", 15);
            total_alerts++;
            continue;
        }

        /* Classify risk */
        classify_risk(a->process, a->port, a->ip, a->risk);

        total_alerts++;
    }

    free(line);
    pclose(fp);
    generate_json();
}

/* ===========================
   MAIN
   =========================== */

int main(void) {
    printf("Puster 3.5 running...\n");
    detect_remote_connections();
    printf("Scan completed: %d connections analyzed.\n", total_alerts);
    return 0;
}
