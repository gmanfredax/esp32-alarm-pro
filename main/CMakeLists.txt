# Colleziona tutti i .c nella cartella main (comodo se aggiungi file spesso)
#file(GLOB MAIN_SRCS "userdb.c" "totp.c" "pn532_spi.c" "auth.c" "alarm_core.c" "web_server.c" "*.c")
file(GLOB MAIN_SRCS "*.c")

set(MAIN_EMBED_TXTFILES
    "certs/server_cert.pem"
    "certs/server_key.pem"
#    "certs/broker_ca.pem"
)

set(MQTT_BROKER_CA_RELATIVE "certs/broker_ca.pem")
set(MQTT_BROKER_CA_ABSOLUTE "${CMAKE_CURRENT_LIST_DIR}/${MQTT_BROKER_CA_RELATIVE}")

if(EXISTS "${MQTT_BROKER_CA_ABSOLUTE}")
    list(APPEND MAIN_EMBED_TXTFILES "${MQTT_BROKER_CA_RELATIVE}")
elseif(CONFIG_MQTT_TRANSPORT_SSL OR CONFIG_MQTT_TRANSPORT_WEBSOCKET_SECURE)
    message(FATAL_ERROR
        "CONFIG_MQTT_TRANSPORT_SSL/WEBSOCKET_SECURE abilitato ma non trovo ${MQTT_BROKER_CA_RELATIVE}. "
        "Copia il certificato CA del broker in ${MQTT_BROKER_CA_ABSOLUTE} oppure disabilita il trasporto TLS/WSS.")
else()
    message(STATUS "MQTT broker CA non trovata (${MQTT_BROKER_CA_ABSOLUTE}), embed ignorato perché TLS MQTT è disabilitato.")
endif()

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
        json
        lwip
        mqtt
        fatfs
        spiffs
    PRIV_REQUIRES
        esp_https_server
        driver
    EMBED_TXTFILES
        ${MAIN_EMBED_TXTFILES}
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE CAN_TEST_BROADCAST=1)

# Genera l’immagine SPIFFS dalla cartella spiffs/
spiffs_create_partition_image(spiffs ${CMAKE_SOURCE_DIR}/spiffs FLASH_IN_PROJECT)
add_custom_target(spiffs DEPENDS spiffs_spiffs_bin)