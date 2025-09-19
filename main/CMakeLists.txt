# Colleziona tutti i .c nella cartella main (comodo se aggiungi file spesso)
file(GLOB MAIN_SRCS "userdb.c" "totp.c" "pn532_spi.c" "auth.c" "alarm_core.c" "web_server.c" "*.c")

idf_component_register(
    SRCS
        ${MAIN_SRCS}
    INCLUDE_DIRS
        "."
    REQUIRES
        mdns
        esp_http_server
        esp_event
        esp_netif
        esp_eth
        esp_driver_i2c
        esp_driver_spi
        esp_driver_gpio
        nvs_flash
        spi_flash
        esp_timer
        esp_system
        json          # <— componente cJSON si chiama "json"
        lwip
        mqtt
        fatfs
        spiffs
    PRIV_REQUIRES
        esp_https_server   # <— trascina da solo esp-tls e mbedtls
    EMBED_TXTFILES
        "certs/server_cert.pem"
        "certs/server_key.pem"
        "certs/broker_ca.pem"
)

# Genera l’immagine SPIFFS dalla cartella spiffs/
spiffs_create_partition_image(spiffs ${CMAKE_SOURCE_DIR}/spiffs FLASH_IN_PROJECT)
add_custom_target(spiffs DEPENDS spiffs_spiffs_bin)