/*
 * ESP32 Wi-Fi scanner with a live browser UI.
 *
 * Two different radios-uses, deliberately kept separate because the chip has
 * exactly one 2.4 GHz radio and can only sit on one channel at a time:
 *
 *   - Access points  : esp_wifi_scan_start() does an active scan that walks all
 *                      13 channels, so the network list is complete.
 *   - Client devices : promiscuous mode captures every frame on the channel the
 *                      station is associated to. Devices on other channels are
 *                      invisible by construction, not by bug.
 *
 * Credentials come from the console (CONFIG_EXAMPLE_WIFI_SSID_PWD_FROM_STDIN),
 * never from the image.
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

#include "protocol_examples_common.h"
#include "oui_table.h"

static const char *TAG = "scanner";

#define MAX_APS      40
#define MAX_CLIENTS  64
#define CLIENT_TTL_S 180
#define JSON_CAP     16384

typedef struct {
    uint8_t  bssid[6];
    char     ssid[33];
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  auth;
} ap_t;

typedef struct {
    uint8_t  mac[6];
    int8_t   rssi;
    uint8_t  channel;
    uint16_t frames;
    int64_t  last_us;
    char     kind[8];
    char     name[40];      /* mDNS hostname, when the device announces one */
} client_t;

static ap_t     s_aps[MAX_APS];
static int      s_ap_count;
static int64_t  s_scan_done_us;
static bool     s_scan_running;

static client_t s_clients[MAX_CLIENTS];
static int      s_client_count;

static SemaphoreHandle_t s_ap_lock;
static portMUX_TYPE      s_cli_lock = portMUX_INITIALIZER_UNLOCKED;

static uint8_t  s_sta_mac[6];
static uint8_t  s_channel;
static char     s_json[JSON_CAP];

static const char *auth_name(wifi_auth_mode_t m)
{
    switch (m) {
    case WIFI_AUTH_OPEN:            return "open";
    case WIFI_AUTH_WEP:             return "WEP";
    case WIFI_AUTH_WPA_PSK:         return "WPA";
    case WIFI_AUTH_WPA2_PSK:        return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/WPA2";
    case WIFI_AUTH_WPA3_PSK:        return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK:   return "WPA2/WPA3";
    case WIFI_AUTH_WAPI_PSK:        return "WAPI";
    default:                        return "other";
    }
}

/* ---------- access points ---------- */

static void on_wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base != WIFI_EVENT || id != WIFI_EVENT_SCAN_DONE) {
        return;
    }

    uint16_t n = 0;
    esp_wifi_scan_get_ap_num(&n);
    if (n > MAX_APS) {
        n = MAX_APS;
    }

    wifi_ap_record_t *recs = calloc(n ? n : 1, sizeof(wifi_ap_record_t));
    if (recs == NULL) {
        s_scan_running = false;
        return;
    }
    if (esp_wifi_scan_get_ap_records(&n, recs) != ESP_OK) {
        n = 0;
    }

    if (xSemaphoreTake(s_ap_lock, pdMS_TO_TICKS(200)) == pdTRUE) {
        s_ap_count = n;
        for (int i = 0; i < n; i++) {
            memcpy(s_aps[i].bssid, recs[i].bssid, 6);
            memcpy(s_aps[i].ssid, recs[i].ssid, sizeof(s_aps[i].ssid) - 1);
            s_aps[i].ssid[sizeof(s_aps[i].ssid) - 1] = '\0';
            s_aps[i].rssi    = recs[i].rssi;
            s_aps[i].channel = recs[i].primary;
            s_aps[i].auth    = recs[i].authmode;
        }
        s_scan_done_us = esp_timer_get_time();
        xSemaphoreGive(s_ap_lock);
    }
    free(recs);
    s_scan_running = false;
    ESP_LOGI(TAG, "scan done: %d access points", n);
}

static void request_scan(void)
{
    if (s_scan_running) {
        return;
    }
    wifi_scan_config_t cfg = {
        .ssid        = NULL,
        .bssid       = NULL,
        .channel     = 0,              /* 0 = all channels */
        .show_hidden = true,
        .scan_type   = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 120,
        .scan_time.active.max = 1500,
    };
    if (esp_wifi_scan_start(&cfg, false) == ESP_OK) {
        s_scan_running = true;
    }
}

/* ---------- client devices ---------- */

static void client_touch(const uint8_t *mac, int8_t rssi, uint8_t ch, const char *kind)
{
    int64_t now = esp_timer_get_time();

    portENTER_CRITICAL(&s_cli_lock);
    int slot = -1;
    for (int i = 0; i < s_client_count; i++) {
        if (memcmp(s_clients[i].mac, mac, 6) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        if (s_client_count < MAX_CLIENTS) {
            slot = s_client_count++;
        } else {
            /* evict the stalest entry */
            int oldest = 0;
            for (int i = 1; i < MAX_CLIENTS; i++) {
                if (s_clients[i].last_us < s_clients[oldest].last_us) {
                    oldest = i;
                }
            }
            slot = oldest;
            s_clients[slot].frames = 0;
        }
        memcpy(s_clients[slot].mac, mac, 6);
        s_clients[slot].frames = 0;
        memset(s_clients[slot].kind, 0, sizeof(s_clients[slot].kind));
        strncpy(s_clients[slot].kind, kind, sizeof(s_clients[slot].kind) - 1);
        s_clients[slot].name[0] = '\0';
    }
    s_clients[slot].rssi    = rssi;
    s_clients[slot].channel = ch;
    s_clients[slot].last_us = now;
    if (s_clients[slot].frames < UINT16_MAX) {
        s_clients[slot].frames++;
    }
    portEXIT_CRITICAL(&s_cli_lock);
}

static void client_set_name(const uint8_t *mac, const char *name)
{
    portENTER_CRITICAL(&s_cli_lock);
    for (int i = 0; i < s_client_count; i++) {
        if (memcmp(s_clients[i].mac, mac, 6) == 0) {
            if (strcmp(s_clients[i].name, name) != 0) {
                strncpy(s_clients[i].name, name, sizeof(s_clients[i].name) - 1);
                s_clients[i].name[sizeof(s_clients[i].name) - 1] = '\0';
                ESP_LOGI(TAG, "name %02x:%02x:%02x:%02x:%02x:%02x -> %s",
                         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                         s_clients[i].name);
            }
            break;
        }
    }
    portEXIT_CRITICAL(&s_cli_lock);
}

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

/*
 * Pull a device name out of an mDNS payload.
 *
 * DNS names are length-prefixed label chains, so instead of walking the record
 * structure (which uses compression pointers we would have to follow) this
 * scans for any valid chain that terminates in ".local" and keeps the first
 * label. Chains starting with '_' are service descriptors, not device names.
 */
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

/* Locate the UDP payload for a given destination port inside an IPv4 or IPv6
 * packet. Returns NULL if this is not such a packet. */
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
        if (nh == 44) {                       /* fragment header */
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

/* mDNS: unencrypted multicast on port 5353, and the only place a phone leaks a
 * human-readable name while merely passing by. */
static void maybe_mdns(const uint8_t *f, int len, int hdr, const uint8_t *tx)
{
    if (hdr + 8 + 20 > len) {
        return;
    }
    const uint8_t *llc = f + hdr;
    if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03)) {
        return;
    }
    int avail = len - (int)((llc + 8) - f);
    int plen  = 0;
    const uint8_t *dns = find_udp(llc + 8, avail, 5353, &plen);
    if (dns == NULL || plen < 13) {
        return;
    }

    char name[40];
    extract_local_name(dns, plen, name, sizeof(name));
    if (name[0] != '\0') {
        client_set_name(tx, name);
    }
}

/* DHCP option 12 carries the hostname the device wants to register. Only seen
 * when a device (re)joins a network, so it is a bonus source, not the main one. */
static void maybe_dhcp(const uint8_t *f, int len, int hdr, const uint8_t *tx)
{
    if (hdr + 8 + 20 > len) {
        return;
    }
    const uint8_t *llc = f + hdr;
    if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 && llc[6] == 0x08 && llc[7] == 0x00)) {
        return;
    }
    int avail = len - (int)((llc + 8) - f);
    int plen  = 0;
    const uint8_t *bp = find_udp(llc + 8, avail, 67, &plen);
    if (bp == NULL || plen < 240 || bp[0] != 1) {      /* 1 = BOOTREQUEST */
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
            client_set_name(tx, name);
            break;
        }
        i += 2 + L;
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
    const uint8_t *tx = f + 10;             /* addr2 = transmitter */

    if (tx[0] & 0x01) {
        return;                              /* group / broadcast */
    }
    if (memcmp(tx, s_sta_mac, 6) == 0) {
        return;                              /* ourselves */
    }
    if (ftype == 0 && subtype == 8) {
        return;                              /* beacon: an AP, the scan covers it */
    }

    const char *kind = "mgmt";
    if (ftype == 2) {
        kind = "data";
    } else if (ftype == 0 && subtype == 4) {
        kind = "probe";
    } else if (ftype == 1) {
        kind = "ctrl";
    }

    client_touch(tx, p->rx_ctrl.rssi, p->rx_ctrl.channel, kind);

    if (ftype == 2) {
        int hdr = 24;
        if ((subtype & 0x08) != 0) {
            hdr += 2;                        /* QoS control field */
        }
        maybe_mdns(f, p->rx_ctrl.sig_len, hdr, tx);
        maybe_dhcp(f, p->rx_ctrl.sig_len, hdr, tx);
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

static void json_ssid(char *dst, size_t dstsz, const char *src)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 1 < dstsz; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') {
            dst[j++] = '.';
        } else {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
}

static int build_json(void)
{
    int off = 0;

    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip = {0};
    bool linked = (netif != NULL) && (esp_netif_get_ip_info(netif, &ip) == ESP_OK) && (ip.ip.addr != 0);

    wifi_ap_record_t ap_rec = {0};
    bool have_ap = (esp_wifi_sta_get_ap_info(&ap_rec) == ESP_OK);
    char ssid[33] = "(none)";
    if (have_ap) {
        memcpy(ssid, ap_rec.ssid, sizeof(ssid));
        ssid[sizeof(ssid) - 1] = '\0';
    }

    int64_t age_s = s_scan_done_us ? (esp_timer_get_time() - s_scan_done_us) / 1000000 : -1;

    off = json_put(s_json, off, JSON_CAP, "{\"heap\":%u,\"scan_age\":%lld,\"sta\":",
                   (unsigned)esp_get_free_heap_size(), (long long)age_s);
    if (linked) {
        off = json_put(s_json, off, JSON_CAP,
                       "{\"ip\":\"%d.%d.%d.%d\",\"ssid\":\"%s\",\"ch\":%u}",
                       (int)(ip.ip.addr & 0xff), (int)((ip.ip.addr >> 8) & 0xff),
                       (int)((ip.ip.addr >> 16) & 0xff), (int)((ip.ip.addr >> 24) & 0xff),
                       ssid, (unsigned)s_channel);
    } else {
        off = json_put(s_json, off, JSON_CAP, "null");
    }

    off = json_put(s_json, off, JSON_CAP, ",\"ap\":[");
    if (xSemaphoreTake(s_ap_lock, pdMS_TO_TICKS(200)) == pdTRUE) {
        for (int i = 0; i < s_ap_count; i++) {
            char clean[33];
            json_ssid(clean, sizeof(clean), s_aps[i].ssid);
            off = json_put(s_json, off, JSON_CAP,
                           "%s{\"ssid\":\"%s\",\"bssid\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
                           "\"ch\":%u,\"rssi\":%d,\"auth\":\"%s\"}",
                           i ? "," : "", clean,
                           s_aps[i].bssid[0], s_aps[i].bssid[1], s_aps[i].bssid[2],
                           s_aps[i].bssid[3], s_aps[i].bssid[4], s_aps[i].bssid[5],
                           s_aps[i].channel, s_aps[i].rssi, auth_name(s_aps[i].auth));
        }
        xSemaphoreGive(s_ap_lock);
    }

    off = json_put(s_json, off, JSON_CAP, "],\"clients\":[");
    int64_t now = esp_timer_get_time();
    int64_t ttl = (int64_t)CLIENT_TTL_S * 1000000;
    bool first = true;

    /* Held for the BSSID lookup below: a MAC that matches a scanned access
     * point is that AP, and its name is the SSID. */
    xSemaphoreTake(s_ap_lock, pdMS_TO_TICKS(200));

    portENTER_CRITICAL(&s_cli_lock);
    for (int i = 0; i < s_client_count; i++) {
        if (now - s_clients[i].last_us > ttl) {
            continue;
        }

        char mdns_name[42];
        json_ssid(mdns_name, sizeof(mdns_name), s_clients[i].name);

        char ap_name[33] = "";
        bool is_ap = false;
        for (int k = 0; k < s_ap_count; k++) {
            if (memcmp(s_aps[k].bssid, s_clients[i].mac, 6) == 0) {
                json_ssid(ap_name, sizeof(ap_name), s_aps[k].ssid);
                is_ap = true;
                break;
            }
        }

        char vendor[20] = "";
        if (!is_ap) {
            if ((s_clients[i].mac[0] & 0x02) != 0) {
                strcpy(vendor, "random");
            } else {
                const char *v = oui_lookup(s_clients[i].mac);
                if (v != NULL) {
                    strncpy(vendor, v, sizeof(vendor) - 1);
                }
            }
        }

        off = json_put(s_json, off, JSON_CAP,
                       "%s{\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"ch\":%u,"
                       "\"rssi\":%d,\"kind\":\"%s\",\"frames\":%u,\"age\":%lld,"
                       "\"name\":\"%s\",\"vendor\":\"%s\",\"ap\":%s}",
                       first ? "" : ",",
                       s_clients[i].mac[0], s_clients[i].mac[1], s_clients[i].mac[2],
                       s_clients[i].mac[3], s_clients[i].mac[4], s_clients[i].mac[5],
                       s_clients[i].channel, s_clients[i].rssi, s_clients[i].kind,
                       (unsigned)s_clients[i].frames,
                       (long long)((now - s_clients[i].last_us) / 1000000),
                       is_ap ? ap_name : mdns_name, vendor, is_ap ? "true" : "false");
        first = false;
    }
    portEXIT_CRITICAL(&s_cli_lock);
    xSemaphoreGive(s_ap_lock);

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

/* ---------- main ---------- */

static void scanner_task(void *arg)
{
    while (true) {
        request_scan();
        vTaskDelay(pdMS_TO_TICKS(15000));
    }
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_ap_lock = xSemaphoreCreateMutex();

    ESP_LOGI(TAG, "connect to Wi-Fi: type  <ssid> <password>  then ENTER");
    ESP_ERROR_CHECK(example_connect());

    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, s_sta_mac));

    wifi_ap_record_t ap_rec = {0};
    if (esp_wifi_sta_get_ap_info(&ap_rec) == ESP_OK) {
        s_channel = ap_rec.primary;
    }

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, WIFI_EVENT_SCAN_DONE, &on_wifi_event, NULL, NULL));

    /* capture every frame on the current channel, management and data only */
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

    static const httpd_uri_t uri_root = { .uri = "/",          .method = HTTP_GET, .handler = handler_root };
    static const httpd_uri_t uri_data = { .uri = "/api/data",  .method = HTTP_GET, .handler = handler_data };
    static const httpd_uri_t uri_scan = { .uri = "/api/scan",  .method = HTTP_GET, .handler = handler_scan };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_root));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_data));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_scan));

    ESP_LOGI(TAG, "open http://<board-ip>/   (promiscuous capture locked to channel %u)",
             (unsigned)s_channel);

    xTaskCreate(scanner_task, "scan_loop", 4096, NULL, 4, NULL);
}
