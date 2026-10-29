/*
 * ESP32 as its own access point, showing who joins it.
 *
 * Why this exists next to wifi_scanner: on a WPA2 network a sniffing station
 * sees only frame headers, because every other client's payload is encrypted
 * with a key it does not hold. As the AP, this board issues those keys, so its
 * own clients' DHCP requests and mDNS announcements are readable and a real
 * device name becomes possible.
 *
 * No credentials are needed at boot: the board creates the network itself.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "esp_timer.h"
#include "nvs_flash.h"

#include "oui_table.h"

static const char *TAG = "ap_scanner";

#define AP_SSID     "ESP32-SCANNER"
#define AP_PASS     "esp32scanner"
#define AP_CHANNEL  6
#define AP_MAX_CONN 4

#define MAX_STA   8
#define MAX_NAMES 16
#define MAX_NETS  32
#define MAX_SDEV  120
#define JSON_CAP  20480

typedef struct {
    uint8_t  mac[6];
    int8_t   rssi;
    int64_t  seen_us;
} sta_t;

typedef struct {
    uint8_t mac[6];
    char    name[40];
} name_t;

typedef struct {
    char     ssid[33];
    uint8_t  bssid[6];
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  auth;
} net_t;

/* A device heard while the radio hopped channels. MAC and channel identify it:
 * the same phone shows up once per channel it was caught on. */
typedef struct {
    uint8_t  mac[6];
    uint8_t  ch;
    int8_t   rssi;
    uint8_t  kind;          /* 0 data, 1 probe, 2 mgmt, 3 ctrl */
    uint16_t hits;
    char     probe[33];     /* SSID this device asked for, when it probes */
} sdev_t;

static sta_t  s_sta[MAX_STA];
static int    s_sta_count;
static name_t s_names[MAX_NAMES];
static int    s_name_count;
static net_t  s_nets[MAX_NETS];
static int    s_net_count;
static int64_t s_scan_us;
static bool   s_scanning;

static sdev_t s_sdev[MAX_SDEV];
static int    s_sdev_count;
static volatile bool s_surveying;
static int64_t s_survey_us;

static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static uint8_t      s_ap_mac[6];
static uint8_t      s_channel = AP_CHANNEL;

static char s_json[JSON_CAP];

static const char *auth_name(wifi_auth_mode_t m)
{
    switch (m) {
    case WIFI_AUTH_OPEN:          return "open";
    case WIFI_AUTH_WEP:           return "WEP";
    case WIFI_AUTH_WPA_PSK:       return "WPA";
    case WIFI_AUTH_WPA2_PSK:      return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:  return "WPA/WPA2";
    case WIFI_AUTH_WPA3_PSK:      return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    default:                      return "other";
    }
}

/* ---------- store a discovered name ---------- */

static void name_store(const uint8_t *mac, const char *name)
{
    portENTER_CRITICAL(&s_lock);
    for (int i = 0; i < s_name_count; i++) {
        if (memcmp(s_names[i].mac, mac, 6) == 0) {
            if (strcmp(s_names[i].name, name) != 0) {
                strncpy(s_names[i].name, name, sizeof(s_names[i].name) - 1);
                s_names[i].name[sizeof(s_names[i].name) - 1] = '\0';
                ESP_LOGI(TAG, "name %02x:%02x:%02x:%02x:%02x:%02x -> %s",
                         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], name);
            }
            portEXIT_CRITICAL(&s_lock);
            return;
        }
    }
    if (s_name_count < MAX_NAMES) {
        memcpy(s_names[s_name_count].mac, mac, 6);
        strncpy(s_names[s_name_count].name, name, sizeof(s_names[0].name) - 1);
        s_names[s_name_count].name[sizeof(s_names[0].name) - 1] = '\0';
        s_name_count++;
        ESP_LOGI(TAG, "name %02x:%02x:%02x:%02x:%02x:%02x -> %s",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], name);
    }
    portEXIT_CRITICAL(&s_lock);
}

static const char *name_for(const uint8_t *mac)
{
    for (int i = 0; i < s_name_count; i++) {
        if (memcmp(s_names[i].mac, mac, 6) == 0) {
            return s_names[i].name;
        }
    }
    return NULL;
}

/* ---------- packet parsing (identical logic to wifi_scanner) ---------- */

static bool printable_run(const uint8_t *p, int n)
{
    for (int i = 0; i < n; i++) {
        if (p[i] < 0x20 || p[i] > 0x7e) {
            return false;
        }
    }
    return true;
}

static bool ends_with_local(const char *s)
{
    size_t n = strlen(s);
    if (n < 6) {
        return false;
    }
    const char *t = s + n - 6;
    return (t[0] == '.' &&
            (t[1] | 0x20) == 'l' && (t[2] | 0x20) == 'o' && (t[3] | 0x20) == 'c' &&
            (t[4] | 0x20) == 'a' && (t[5] | 0x20) == 'l');
}

static void extract_local_name(const uint8_t *d, int len, char *out, size_t outsz)
{
    out[0] = '\0';

    for (int p = 0; p + 2 < len; p++) {
        int  q = p, ti = 0, labels = 0;
        bool ok = true;
        char tmp[80];

        while (q < len) {
            uint8_t L = d[q];
            if (L == 0) {
                break;
            }
            if (L == 0xC0 || L > 63 || q + 1 + L > len) {
                ok = false;
                break;
            }
            if (!printable_run(d + q + 1, L)) {
                ok = false;
                break;
            }
            if (ti + L + 2 >= (int)sizeof(tmp)) {
                ok = false;
                break;
            }
            if (ti) {
                tmp[ti++] = '.';
            }
            memcpy(tmp + ti, d + q + 1, L);
            ti += L;
            labels++;
            q += 1 + L;
        }
        tmp[ti] = '\0';

        if (!ok || labels < 2 || ti < 7 || tmp[0] == '_' || !ends_with_local(tmp)) {
            continue;
        }

        char dev[40];
        int i = 0;
        while (tmp[i] != '\0' && tmp[i] != '.' && i < (int)sizeof(dev) - 1) {
            dev[i] = tmp[i];
            i++;
        }
        dev[i] = '\0';
        if (i >= 3 && strlen(dev) > strlen(out)) {
            strncpy(out, dev, outsz - 1);
            out[outsz - 1] = '\0';
        }
    }
}

static const uint8_t *find_udp(const uint8_t *l3, int avail, int want_port, int *plen)
{
    if (avail < 20) {
        return NULL;
    }

    if ((l3[0] >> 4) == 4) {
        int ihl = (l3[0] & 0x0f) * 4;
        if (ihl < 20 || ihl > avail || l3[9] != 17) {
            return NULL;
        }
        int total = (l3[2] << 8) | l3[3];
        if (total > avail) {
            total = avail;
        }
        if (total < ihl + 8) {
            return NULL;
        }
        const uint8_t *udp = l3 + ihl;
        if (((udp[2] << 8) | udp[3]) != want_port) {
            return NULL;
        }
        *plen = total - ihl - 8;
        return udp + 8;
    }

    if ((l3[0] >> 4) == 6) {
        if (avail < 48) {
            return NULL;
        }
        int     pl   = (l3[4] << 8) | l3[5];
        uint8_t nh   = l3[6];
        const uint8_t *udp = l3 + 40;
        int     head = 40;
        if (nh == 44) {
            nh   = l3[40];
            udp += 8;
            head += 8;
            pl   -= 8;
        }
        if (nh != 17 || pl < 8) {
            return NULL;
        }
        if (head + pl > avail) {
            pl = avail - head;
        }
        if (pl < 8) {
            return NULL;
        }
        if (((udp[2] << 8) | udp[3]) != want_port) {
            return NULL;
        }
        *plen = pl - 8;
        return udp + 8;
    }
    return NULL;
}

static void maybe_mdns(const uint8_t *f, int len, int hdr, const uint8_t *tx)
{
    if (hdr + 8 + 20 > len) {
        return;
    }
    const uint8_t *llc = f + hdr;
    if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03)) {
        return;
    }
    int plen = 0;
    const uint8_t *dns = find_udp(llc + 8, len - (int)((llc + 8) - f), 5353, &plen);
    if (dns == NULL || plen < 13) {
        return;
    }
    char name[40];
    extract_local_name(dns, plen, name, sizeof(name));
    if (name[0] != '\0') {
        name_store(tx, name);
    }
}

static void maybe_dhcp(const uint8_t *f, int len, int hdr, const uint8_t *tx)
{
    if (hdr + 8 + 20 > len) {
        return;
    }
    const uint8_t *llc = f + hdr;
    if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 && llc[6] == 0x08 && llc[7] == 0x00)) {
        return;
    }
    int plen = 0;
    const uint8_t *bp = find_udp(llc + 8, len - (int)((llc + 8) - f), 67, &plen);
    if (bp == NULL || plen < 240 || bp[0] != 1) {
        return;
    }
    if (!(bp[236] == 0x63 && bp[237] == 0x82 && bp[238] == 0x53 && bp[239] == 0x63)) {
        return;
    }
    for (int i = 240; i + 1 < plen; ) {
        uint8_t code = bp[i];
        if (code == 0) {
            i++;
            continue;
        }
        if (code == 255) {
            break;
        }
        uint8_t L = bp[i + 1];
        if (i + 2 + L > plen) {
            break;
        }
        if (code == 12 && L >= 3 && printable_run(bp + i + 2, L)) {
            char name[40];
            int n = L < (int)sizeof(name) - 1 ? L : (int)sizeof(name) - 1;
            memcpy(name, bp + i + 2, n);
            name[n] = '\0';
            name_store(tx, name);
            break;
        }
        i += 2 + L;
    }
}

static void survey_store(const uint8_t *mac, uint8_t ch, int8_t rssi, uint8_t kind,
                         const char *probe)
{
    portENTER_CRITICAL(&s_lock);
    for (int i = 0; i < s_sdev_count; i++) {
        if (s_sdev[i].ch == ch && memcmp(s_sdev[i].mac, mac, 6) == 0) {
            s_sdev[i].rssi = rssi;
            s_sdev[i].kind = kind;
            if (s_sdev[i].hits < UINT16_MAX) {
                s_sdev[i].hits++;
            }
            if (probe != NULL && probe[0] != '\0') {
                strncpy(s_sdev[i].probe, probe, sizeof(s_sdev[i].probe) - 1);
                s_sdev[i].probe[sizeof(s_sdev[i].probe) - 1] = '\0';
            }
            portEXIT_CRITICAL(&s_lock);
            return;
        }
    }
    if (s_sdev_count < MAX_SDEV) {
        int i = s_sdev_count++;
        memcpy(s_sdev[i].mac, mac, 6);
        s_sdev[i].ch   = ch;
        s_sdev[i].rssi = rssi;
        s_sdev[i].kind = kind;
        s_sdev[i].hits = 1;
        s_sdev[i].probe[0] = '\0';
        if (probe != NULL && probe[0] != '\0') {
            strncpy(s_sdev[i].probe, probe, sizeof(s_sdev[i].probe) - 1);
        }
    }
    portEXIT_CRITICAL(&s_lock);
}

/* A probe request is a management frame, so it is never encrypted. The SSID
 * element (id 0) names the network the device is looking for. */
static void parse_probe_ssid(const uint8_t *f, int len, char *out, size_t outsz)
{
    out[0] = '\0';
    int p = 24;                       /* probe request has no fixed parameters */
    while (p + 2 <= len) {
        uint8_t id  = f[p];
        uint8_t iel = f[p + 1];
        if (p + 2 + iel > len) {
            break;
        }
        if (id == 0) {                /* SSID element */
            if (iel == 0) {
                return;               /* wildcard probe */
            }
            int n = iel < (int)outsz - 1 ? iel : (int)outsz - 1;
            for (int i = 0; i < n; i++) {
                unsigned char c = f[p + 2 + i];
                out[i] = (c < 0x20 || c > 0x7e) ? '.' : (char)c;
            }
            out[n] = '\0';
            return;
        }
        p += 2 + iel;
    }
}

static void on_frame(void *buf, wifi_promiscuous_pkt_type_t type)
{
    const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *f = p->payload;

    if (p->rx_ctrl.sig_len < 24) {
        return;
    }

    uint8_t fc0     = f[0];
    int     ftype   = (fc0 >> 2) & 0x3;
    int     subtype = (fc0 >> 4) & 0xF;
    const uint8_t *tx = f + 10;

    if (tx[0] & 0x01) {
        return;
    }
    if (memcmp(tx, s_ap_mac, 6) == 0) {
        return;                              /* our own beacons and traffic */
    }
    if (ftype == 0 && subtype == 8) {
        return;                              /* other APs' beacons: covered by the scan */
    }

    uint8_t kind = 2;
    if (ftype == 2) {
        kind = 0;
    } else if (ftype == 0 && subtype == 4) {
        kind = 1;
    } else if (ftype == 1) {
        kind = 3;
    }

    if (s_surveying) {
        char probe[33] = "";
        if (ftype == 0 && subtype == 4) {
            parse_probe_ssid(f, p->rx_ctrl.sig_len, probe, sizeof(probe));
        }
        survey_store(tx, p->rx_ctrl.channel, p->rx_ctrl.rssi, kind,
                     probe[0] != '\0' ? probe : NULL);
    }

    if (ftype == 2) {
        int hdr = 24;
        if ((subtype & 0x08) != 0) {
            hdr += 2;
        }
        maybe_mdns(f, p->rx_ctrl.sig_len, hdr, tx);
        maybe_dhcp(f, p->rx_ctrl.sig_len, hdr, tx);
    }
}

/* ---------- associated stations ---------- */

static void refresh_stations(void)
{
    wifi_sta_list_t list = {0};
    if (esp_wifi_ap_get_sta_list(&list) != ESP_OK) {
        return;
    }

    portENTER_CRITICAL(&s_lock);
    s_sta_count = list.num > MAX_STA ? MAX_STA : list.num;
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < s_sta_count; i++) {
        memcpy(s_sta[i].mac, list.sta[i].mac, 6);
        s_sta[i].rssi    = list.sta[i].rssi;
        s_sta[i].seen_us = now;
    }
    portEXIT_CRITICAL(&s_lock);
}

/* ---------- network scan (manual only: it pauses our own beacons) ---------- */

static void on_wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base != WIFI_EVENT || id != WIFI_EVENT_SCAN_DONE) {
        return;
    }
    uint16_t n = 0;
    esp_wifi_scan_get_ap_num(&n);
    if (n > MAX_NETS) {
        n = MAX_NETS;
    }
    wifi_ap_record_t *recs = calloc(n ? n : 1, sizeof(wifi_ap_record_t));
    if (recs == NULL) {
        s_scanning = false;
        return;
    }
    if (esp_wifi_scan_get_ap_records(&n, recs) == ESP_OK) {
        portENTER_CRITICAL(&s_lock);
        s_net_count = n;
        for (int i = 0; i < n; i++) {
            memcpy(s_nets[i].bssid, recs[i].bssid, 6);
            memcpy(s_nets[i].ssid, recs[i].ssid, sizeof(s_nets[i].ssid) - 1);
            s_nets[i].ssid[sizeof(s_nets[i].ssid) - 1] = '\0';
            s_nets[i].rssi    = recs[i].rssi;
            s_nets[i].channel = recs[i].primary;
            s_nets[i].auth    = recs[i].authmode;
        }
        s_scan_us = esp_timer_get_time();
        portEXIT_CRITICAL(&s_lock);

        /* Per-channel breakdown, so the channel plan is visible without the
         * phone: an active scan visits every channel in one pass. */
        for (int ch = 1; ch <= 14; ch++) {
            int cnt = 0;
            for (int i = 0; i < n; i++) {
                if (recs[i].primary == ch) {
                    cnt++;
                }
            }
            if (cnt > 0) {
                ESP_LOGI(TAG, "channel %2d: %d AP%s", ch, cnt, cnt == 1 ? "" : "s");
                for (int i = 0; i < n; i++) {
                    if (recs[i].primary == ch) {
                        ESP_LOGI(TAG, "    ch%2d  %4d dBm  %-24.24s  %02x:%02x:%02x:%02x:%02x:%02x",
                                 ch, recs[i].rssi, (const char *)recs[i].ssid,
                                 recs[i].bssid[0], recs[i].bssid[1], recs[i].bssid[2],
                                 recs[i].bssid[3], recs[i].bssid[4], recs[i].bssid[5]);
                    }
                }
            }
        }
    }
    free(recs);
    ESP_LOGI(TAG, "scan complete: %d APs", n);
    s_scanning = false;
}

static void request_scan(void)
{
    if (s_scanning) {
        return;
    }
    wifi_scan_config_t cfg = {
        .show_hidden = true,
        .scan_type   = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 120,
        .scan_time.active.max = 1200,
    };
    esp_err_t err = esp_wifi_scan_start(&cfg, false);
    if (err == ESP_OK) {
        s_scanning = true;
    } else {
        /* Classic ESP32 refuses to scan in pure AP mode; the interface must be
         * APSTA even if the station side never associates. */
        ESP_LOGW(TAG, "scan_start failed: %s", esp_err_to_name(err));
    }
}

/* ---------- JSON ---------- */

static int json_put(char *out, int off, int cap, const char *fmt, ...)
{
    if (off >= cap - 1) {
        return off;
    }
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(out + off, cap - off, fmt, ap);
    va_end(ap);
    if (w < 0) {
        return off;
    }
    off += w;
    return off > cap - 1 ? cap - 1 : off;
}

static void json_clean(char *dst, size_t dstsz, const char *src)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 1 < dstsz; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[j++] = (c < 0x20 || c > 0x7e || c == '"' || c == '\\') ? '.' : (char)c;
    }
    dst[j] = '\0';
}

static int build_json(void)
{
    int off = 0;
    int64_t age = s_scan_us ? (esp_timer_get_time() - s_scan_us) / 1000000 : -1;
    int64_t sage = s_survey_us ? (esp_timer_get_time() - s_survey_us) / 1000000 : -1;

    off = json_put(s_json, off, JSON_CAP,
                   "{\"ap\":{\"ssid\":\"%s\",\"ip\":\"192.168.4.1\",\"ch\":%u},\"heap\":%u,"
                   "\"scan_age\":%lld,\"survey_age\":%lld,\"surveying\":%s,\"net\":[",
                   AP_SSID, (unsigned)s_channel, (unsigned)esp_get_free_heap_size(),
                   (long long)age, (long long)sage, s_surveying ? "true" : "false");

    portENTER_CRITICAL(&s_lock);
    for (int i = 0; i < s_net_count; i++) {
        char clean[33];
        json_clean(clean, sizeof(clean), s_nets[i].ssid);
        off = json_put(s_json, off, JSON_CAP,
                       "%s{\"ssid\":\"%s\",\"bssid\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
                       "\"ch\":%u,\"rssi\":%d,\"auth\":\"%s\"}",
                       i ? "," : "", clean,
                       s_nets[i].bssid[0], s_nets[i].bssid[1], s_nets[i].bssid[2],
                       s_nets[i].bssid[3], s_nets[i].bssid[4], s_nets[i].bssid[5],
                       s_nets[i].channel, s_nets[i].rssi, auth_name(s_nets[i].auth));
    }

    off = json_put(s_json, off, JSON_CAP, "],\"devices\":[");
    for (int i = 0; i < s_sta_count; i++) {
        const char *nm = name_for(s_sta[i].mac);
        char clean[42] = "";
        if (nm != NULL) {
            json_clean(clean, sizeof(clean), nm);
        }

        char vendor[20] = "";
        if ((s_sta[i].mac[0] & 0x02) != 0) {
            strcpy(vendor, "random");
        } else {
            const char *v = oui_lookup(s_sta[i].mac);
            if (v != NULL) {
                strncpy(vendor, v, sizeof(vendor) - 1);
            }
        }

        off = json_put(s_json, off, JSON_CAP,
                       "%s{\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"rssi\":%d,"
                       "\"name\":\"%s\",\"vendor\":\"%s\",\"connected\":true}",
                       i ? "," : "",
                       s_sta[i].mac[0], s_sta[i].mac[1], s_sta[i].mac[2],
                       s_sta[i].mac[3], s_sta[i].mac[4], s_sta[i].mac[5],
                       s_sta[i].rssi, clean, vendor);
    }
    portEXIT_CRITICAL(&s_lock);

    off = json_put(s_json, off, JSON_CAP, "],\"sdev\":[");
    portENTER_CRITICAL(&s_lock);
    for (int i = 0; i < s_sdev_count; i++) {
        const char *nm = name_for(s_sdev[i].mac);
        char clean[42] = "";
        if (nm != NULL) {
            json_clean(clean, sizeof(clean), nm);
        }
        char vendor[20] = "";
        if ((s_sdev[i].mac[0] & 0x02) != 0) {
            strcpy(vendor, "random");
        } else {
            const char *v = oui_lookup(s_sdev[i].mac);
            if (v != NULL) {
                strncpy(vendor, v, sizeof(vendor) - 1);
            }
        }
        off = json_put(s_json, off, JSON_CAP,
                       "%s{\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"ch\":%u,\"rssi\":%d,"
                       "\"kind\":%u,\"hits\":%u,\"name\":\"%s\",\"vendor\":\"%s\",\"probe\":\"%s\"}",
                       i ? "," : "",
                       s_sdev[i].mac[0], s_sdev[i].mac[1], s_sdev[i].mac[2],
                       s_sdev[i].mac[3], s_sdev[i].mac[4], s_sdev[i].mac[5],
                       s_sdev[i].ch, s_sdev[i].rssi, s_sdev[i].kind, s_sdev[i].hits,
                       clean, vendor, s_sdev[i].probe);
    }
    portEXIT_CRITICAL(&s_lock);

    off = json_put(s_json, off, JSON_CAP, "]}");
    return off;
}

/* ---------- HTTP ---------- */

extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[]   asm("_binary_index_html_end");

static esp_err_t handler_root(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, (const char *)index_html_start,
                           index_html_end - index_html_start);
}

static esp_err_t handler_data(httpd_req_t *req)
{
    int len = build_json();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, s_json, len);
}

static esp_err_t handler_scan(httpd_req_t *req)
{
    request_scan();
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static void survey_task(void *arg);

static esp_err_t handler_survey(httpd_req_t *req)
{
    if (!s_surveying) {
        xTaskCreate(survey_task, "survey", 4096, NULL, 4, NULL);
    }
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static void apply_ap_config(void)
{
    wifi_config_t ap = {
        .ap = {
            .ssid           = AP_SSID,
            .password       = AP_PASS,
            .ssid_len       = strlen(AP_SSID),
            .channel        = AP_CHANNEL,
            .max_connection = AP_MAX_CONN,
            .authmode       = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg        = { .required = false },
        },
    };
    esp_wifi_set_config(WIFI_IF_AP, &ap);
}

/* Devices cannot be discovered by scanning: the radio has to sit on a channel
 * and capture whatever is transmitting there. So this drops the AP, walks the
 * band, then brings the AP back — the page is unreachable for ~20 seconds. */
static void survey_task(void *arg)
{
    ESP_LOGW(TAG, "device sweep: hopping 1-13, this AP drops for about 20s");

    portENTER_CRITICAL(&s_lock);
    s_sdev_count = 0;
    portEXIT_CRITICAL(&s_lock);

    s_surveying = true;
    esp_wifi_set_mode(WIFI_MODE_STA);
    vTaskDelay(pdMS_TO_TICKS(300));

    for (int ch = 1; ch <= 13; ch++) {
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(1300));
    }

    s_surveying = false;
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    vTaskDelay(pdMS_TO_TICKS(200));
    apply_ap_config();
    esp_wifi_set_channel(AP_CHANNEL, WIFI_SECOND_CHAN_NONE);
    s_survey_us = esp_timer_get_time();

    ESP_LOGI(TAG, "sweep done: %d device sightings", s_sdev_count);
    for (int ch = 1; ch <= 13; ch++) {
        int cnt = 0;
        for (int i = 0; i < s_sdev_count; i++) {
            if (s_sdev[i].ch == ch) {
                cnt++;
            }
        }
        if (cnt > 0) {
            ESP_LOGI(TAG, "  ch%2d: %d device%s", ch, cnt, cnt == 1 ? "" : "s");
            for (int i = 0; i < s_sdev_count; i++) {
                if (s_sdev[i].ch == ch) {
                    ESP_LOGI(TAG, "      %4d dBm kind=%u hits=%u  %02x:%02x:%02x:%02x:%02x:%02x%s%s",
                             s_sdev[i].rssi, s_sdev[i].kind, s_sdev[i].hits,
                             s_sdev[i].mac[0], s_sdev[i].mac[1], s_sdev[i].mac[2],
                             s_sdev[i].mac[3], s_sdev[i].mac[4], s_sdev[i].mac[5],
                             s_sdev[i].probe[0] ? "  looking for " : "",
                             s_sdev[i].probe);
                }
            }
        }
    }
    vTaskDelete(NULL);
}

static void refresh_task(void *arg)
{
    while (true) {
        refresh_stations();
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}

/* One sweep at boot so the page is populated without anyone pressing Scan.
 * Deliberately not periodic: a scan suspends our own beacons for a second or
 * two and can drop the client that is looking at the page. */
static void boot_scan_task(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(3000));
    request_scan();
    vTaskDelay(pdMS_TO_TICKS(9000));
    /* One device sweep at boot too, so the first page load has both tables.
     * This is the only automatic one: it drops the AP for ~20s. */
    xTaskCreate(survey_task, "survey", 4096, NULL, 4, NULL);
    vTaskDelete(NULL);
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_ap();
    /* The station netif is never associated; it exists so the interface can be
     * APSTA, which is the only mode in which ESP32 will scan while serving. */
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wcfg));

    wifi_config_t ap = {
        .ap = {
            .ssid           = AP_SSID,
            .password       = AP_PASS,
            .ssid_len       = strlen(AP_SSID),
            .channel        = AP_CHANNEL,
            .max_connection = AP_MAX_CONN,
            .authmode       = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg        = { .required = false },
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, s_ap_mac));
    uint8_t primary = 0;
    wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
    if (esp_wifi_get_channel(&primary, &second) == ESP_OK) {
        s_channel = primary;
    }

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, WIFI_EVENT_SCAN_DONE, &on_wifi_event, NULL, NULL));

    /* Our clients' frames are encrypted with keys this board issued, so their
     * DHCP and mDNS payloads are readable here — unlike in station mode. */
    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filt));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&on_frame));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    httpd_handle_t server = NULL;
    httpd_config_t hcfg = HTTPD_DEFAULT_CONFIG();
    hcfg.lru_purge_enable = true;
    ESP_ERROR_CHECK(httpd_start(&server, &hcfg));

    static const httpd_uri_t uri_root = { .uri = "/",         .method = HTTP_GET, .handler = handler_root };
    static const httpd_uri_t uri_data = { .uri = "/api/data", .method = HTTP_GET, .handler = handler_data };
    static const httpd_uri_t uri_scan = { .uri = "/api/scan",   .method = HTTP_GET, .handler = handler_scan };
    static const httpd_uri_t uri_srv  = { .uri = "/api/survey", .method = HTTP_GET, .handler = handler_survey };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_root));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_data));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_scan));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_srv));

    ESP_LOGI(TAG, "AP \"%s\" up on channel %u, password \"%s\"", AP_SSID, (unsigned)s_channel, AP_PASS);
    ESP_LOGI(TAG, "join it, then open http://192.168.4.1/");

    xTaskCreate(refresh_task, "stations", 3072, NULL, 4, NULL);
    xTaskCreate(boot_scan_task, "boot_scan", 3072, NULL, 3, NULL);
}
