# Colleziona tutti i .c nella cartella main (comodo se aggiungi file spesso)
# In alternativa, elenca i file uno per uno per build più deterministiche.
file(GLOB MAIN_SRCS
    "*.c"
)

idf_component_register(
    SRCS
        ${MAIN_SRCS}
        # Se preferisci espliciti, sostituisci la riga sopra con:
        # "ethernet.c"
        # "web_server.c"
        # "mqtt_client.c"
        # "totp.c"
        # "pn532_spi.c"
        # "main.c"
    INCLUDE_DIRS
        "."
    REQUIRES
        mdns
        esp_http_server
        esp_event
        esp_netif
        esp_eth
        esp_driver_spi
        esp_driver_gpio
        nvs_flash
        spi_flash
        esp_timer
        esp_system
        json
        lwip
        mqtt
        driver
        fatfs
        spiffs
)
