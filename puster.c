#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define MAX_ALERTAS 500

/* ===========================
   ESTRUCTURA DE ALERTA
   =========================== */

typedef struct {
    char proceso[128];
    char pid[16];
    char ip[128];
    char puerto[16];
    char protocolo[8];
    char ip_local[128];
    char puerto_local[16];
    char riesgo[16];
} Alerta;

Alerta alertas[MAX_ALERTAS];
int total_alertas = 0;

/* ===========================
   WHITELIST DE PROCESOS
   =========================== */

const char* whitelist[] = {
    "firefox", "firefox-esr", "steam", "electron", "chrome", "chromium",
    "systemd", "NetworkManager", "thunderbird", "discord",
    "telegram-desktop", "signal-desktop", "spotify", "slack",
    "code", "code-oss", "opencode", "obsidian", "mysql", "postgres",
    NULL
};

/* ===========================
   PUERTOS CONSIDERADOS PELIGROSOS
   =========================== */

int es_puerto_peligroso(int puerto) {
    int peligrosos[] = {
        4444, 1337, 9001, 31337, 5555, 6666, 6667,
        4443, 4445, 1234, 2345, 3456, 4567, 5678,
        10001, 10002, 20000, 30000
    };
    int n = sizeof(peligrosos) / sizeof(peligrosos[0]);
    for (int i = 0; i < n; i++) {
        if (puerto == peligrosos[i]) return 1;
    }
    return 0;
}

/* ===========================
   LIMPIEZA DE CADENAS
   =========================== */

void limpiar_cadena(char *str) {
    str[strcspn(str, "\n")] = 0;
    str[strcspn(str, "\r")] = 0;
}

void sanitizar_json(char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == '\"') str[i] = '\'';
        if (str[i] == '\\') str[i] = '/';
    }
}

/* ===========================
   TIMESTAMP
   =========================== */

void obtener_timestamp(char *buffer, size_t size) {
    time_t ahora = time(NULL);
    struct tm *t = localtime(&ahora);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", t);
}

/* ===========================
   DETECCION DE IP PRIVADA
   =========================== */

int es_ip_privada(const char *ip) {
    if (strncmp(ip, "192.168.", 8) == 0) return 1;
    if (strncmp(ip, "10.", 3) == 0) return 1;
    if (strncmp(ip, "172.", 4) == 0) {
        int segundo = atoi(ip + 4);
        if (segundo >= 16 && segundo <= 31) return 1;
    }
    if (strcmp(ip, "127.0.0.1") == 0) return 1;
    if (strcmp(ip, "::1") == 0) return 1;
    if (strstr(ip, "::ffff:192.168.") != NULL) return 1;
    return 0;
}

/* ===========================
   WHITELIST
   =========================== */

int en_whitelist(const char *proceso) {
    for (int i = 0; whitelist[i] != NULL; i++) {
        if (strcmp(proceso, whitelist[i]) == 0) return 1;
    }
    return 0;
}

/* ===========================
   CLASIFICACION DE RIESGO
   =========================== */

void clasificar_riesgo(const char *proceso, const char *puerto,
                       const char *ip, char *resultado) {
    int puerto_num = atoi(puerto);
    int es_externo = !es_ip_privada(ip);
    int es_sospechoso = 0;
    if (strcmp(proceso, "bash") == 0 || strcmp(proceso, "sh") == 0 ||
        strcmp(proceso, "nc") == 0 || strcmp(proceso, "netcat") == 0 ||
        strcmp(proceso, "python") == 0 || strcmp(proceso, "perl") == 0 ||
        strcmp(proceso, "ruby") == 0 || strcmp(proceso, "ncat") == 0 ||
        strcmp(proceso, "socat") == 0 || strcmp(proceso, "nmap") == 0) {
        es_sospechoso = 1;
    }

    /* 1. Puerto peligroso conocido -> HIGH */
    if (es_puerto_peligroso(puerto_num)) {
        strcpy(resultado, "HIGH");
        return;
    }

    /* 2. Proceso sospechoso (shells, herramientas red) -> HIGH */
    if (es_sospechoso) {
        strcpy(resultado, "HIGH");
        return;
    }

    /* 3. Proceso en whitelist (navegadores, system, etc.) -> LOW */
    if (en_whitelist(proceso)) {
        strcpy(resultado, "LOW");
        return;
    }

    /* 4. IP privada + puerto comun -> LOW */
    if (!es_externo && (puerto_num == 80 || puerto_num == 443 ||
                        puerto_num == 53 || puerto_num == 22 ||
                        puerto_num == 3306 || puerto_num == 5432)) {
        strcpy(resultado, "LOW");
        return;
    }

    /* 5. IP externa + puerto comun (web, DNS, SSH) -> MEDIUM */
    if (puerto_num == 80 || puerto_num == 443 ||
        puerto_num == 53 || puerto_num == 22) {
        strcpy(resultado, "MEDIUM");
        return;
    }

    /* 6. IP privada + puerto alto -> MEDIUM */
    if (!es_externo) {
        strcpy(resultado, "MEDIUM");
        return;
    }

    /* 7. IP externa + puerto alto -> HIGH */
    strcpy(resultado, "HIGH");
}

/* ===========================
   GENERAR JSON
   =========================== */

void generar_json() {
    FILE *json = fopen("monitor_data.json", "w");
    if (json == NULL) return;

    char timestamp[64];
    obtener_timestamp(timestamp, sizeof(timestamp));

    int count_low = 0, count_medium = 0, count_high = 0;
    for (int i = 0; i < total_alertas; i++) {
        if (strcmp(alertas[i].riesgo, "LOW") == 0) count_low++;
        else if (strcmp(alertas[i].riesgo, "MEDIUM") == 0) count_medium++;
        else if (strcmp(alertas[i].riesgo, "HIGH") == 0) count_high++;
    }

    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    fprintf(json, "{\n");
    fprintf(json, "  \"metadata\": {\n");
    fprintf(json, "    \"tool\": \"Puster 3.5\",\n");
    fprintf(json, "    \"hostname\": \"%s\",\n", hostname);
    fprintf(json, "    \"timestamp\": \"%s\"\n", timestamp);
    fprintf(json, "  },\n");
    fprintf(json, "  \"summary\": {\n");
    fprintf(json, "    \"total_connections\": %d,\n", total_alertas);
    fprintf(json, "    \"low\": %d,\n", count_low);
    fprintf(json, "    \"medium\": %d,\n", count_medium);
    fprintf(json, "    \"high\": %d\n", count_high);
    fprintf(json, "  },\n");
    fprintf(json, "  \"alerts\": [\n");

    for (int i = 0; i < total_alertas; i++) {
        sanitizar_json(alertas[i].proceso);
        sanitizar_json(alertas[i].ip);
        sanitizar_json(alertas[i].puerto);
        sanitizar_json(alertas[i].protocolo);
        sanitizar_json(alertas[i].ip_local);
        sanitizar_json(alertas[i].puerto_local);
        sanitizar_json(alertas[i].pid);

        fprintf(json, "    {\n");
        fprintf(json, "      \"process\": \"%s\",\n", alertas[i].proceso);
        fprintf(json, "      \"pid\": \"%s\",\n", alertas[i].pid);
        fprintf(json, "      \"protocol\": \"%s\",\n", alertas[i].protocolo);
        fprintf(json, "      \"remote_ip\": \"%s\",\n", alertas[i].ip);
        fprintf(json, "      \"remote_port\": \"%s\",\n", alertas[i].puerto);
        fprintf(json, "      \"local_ip\": \"%s\",\n", alertas[i].ip_local);
        fprintf(json, "      \"local_port\": \"%s\",\n", alertas[i].puerto_local);
        fprintf(json, "      \"risk\": \"%s\"\n", alertas[i].riesgo);

        if (i == total_alertas - 1)
            fprintf(json, "    }\n");
        else
            fprintf(json, "    },\n");
    }

    fprintf(json, "  ]\n");
    fprintf(json, "}\n");

    fclose(json);
}

/* ===========================
   DETECCION DE CONEXIONES
   =========================== */

void detectar_conexiones_remotas() {
    total_alertas = 0;

    /* Escanea conexiones TCP/UDP establecidas/activas */
    FILE *fp = popen("ss -tunp 2>/dev/null | tail -n +2", "r");
    if (fp == NULL) return;

    char buffer[2048];

    while (fgets(buffer, sizeof(buffer), fp) != NULL && total_alertas < MAX_ALERTAS) {
        if (strstr(buffer, "LISTEN") != NULL) continue;

        Alerta *a = &alertas[total_alertas];
        memset(a, 0, sizeof(Alerta));

        /*
         * Formato ss: netid state recv send local:port remote:port [users]
         * Ej: tcp ESTAB 0 0 192.168.1.2:37450 151.101.53.91:443 users:(("firefox",...))
         */
        char netid[16], recv[16], send[16], local_s[128], remote_s[128], users[512];
        char state[16];

        int n = sscanf(buffer, "%15s %15s %15s %15s %127s %127s %511[^\n]",
                       netid, state, recv, send, local_s, remote_s, users);

        if (n < 6) continue;

        strcpy(a->protocolo, netid);

        /* Procesar direccion remota */
        char *rdp = strrchr(remote_s, ':');
        if (rdp != NULL) {
            *rdp = '\0';
            strcpy(a->ip, remote_s);
            strcpy(a->puerto, rdp + 1);
        } else {
            strcpy(a->ip, remote_s);
            strcpy(a->puerto, "?");
        }

        /* Procesar direccion local */
        char *ldp = strrchr(local_s, ':');
        if (ldp != NULL) {
            *ldp = '\0';
            strcpy(a->ip_local, local_s);
            strcpy(a->puerto_local, ldp + 1);
        }

        /* Extraer proceso y PID desde users */
        if (n >= 7 && strlen(users) > 0) {
            char *proc_start = strstr(users, "users:((");
            if (proc_start != NULL) {
                proc_start += 8; /* saltar "users:((" */
                if (*proc_start == '\"') proc_start++; /* saltar comilla inicial */
                char *proc_end = strchr(proc_start, '\"'); /* buscar comilla de cierre */
                if (proc_end != NULL) {
                    int plen = (int)(proc_end - proc_start);
                    if (plen > 127) plen = 127;
                    strncpy(a->proceso, proc_start, plen);
                    a->proceso[plen] = '\0';
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

        /* Limpiar %scope_id de IPv6 */
        char *porcentaje = strchr(a->ip, '%');
        if (porcentaje != NULL) *porcentaje = '\0';
        porcentaje = strchr(a->ip_local, '%');
        if (porcentaje != NULL) *porcentaje = '\0';

        if (strlen(a->proceso) == 0)
            strcpy(a->proceso, "unknown");

        if (strlen(a->pid) == 0)
            strcpy(a->pid, "-");

        /* Saltar conexiones sin remote IP valida (bound sockets, etc.) */
        if (strcmp(a->ip, "0") == 0 || strcmp(a->ip, "0.0.0.0") == 0 ||
            strcmp(a->ip, "::") == 0 || strlen(a->ip) == 0 ||
            strcmp(a->puerto, "?") == 0) {
            continue;
        }

        /* Si es solo loopback local (::1), marcar como LOW */
        if (strcmp(a->ip, "::1") == 0) {
            strcpy(a->riesgo, "LOW");
            total_alertas++;
            continue;
        }

        /* Clasificar riesgo */
        clasificar_riesgo(a->proceso, a->puerto, a->ip, a->riesgo);

        total_alertas++;
    }

    pclose(fp);
    generar_json();
}

/* ===========================
   MAIN
   =========================== */

int main() {
    printf("Puster 3.5 ejecutandose...\n");
    detectar_conexiones_remotas();
    printf("Escaneo completado: %d conexiones analizadas.\n", total_alertas);
    return 0;
}
