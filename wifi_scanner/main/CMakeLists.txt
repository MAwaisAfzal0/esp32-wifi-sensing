idf_component_register(SRC_DIRS "."
                       INCLUDE_DIRS "."
                       EMBED_FILES "index.html"
                       REQUIRES esp_http_server esp_wifi esp_netif nvs_flash esp_timer protocol_examples_common)
