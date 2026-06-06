# Colleziona tutti i .c nella cartella main (comodo se aggiungi file spesso)
#file(GLOB MAIN_SRCS "system_time.c" "network_manager.c" "ethernet.c" "scenes.c" "system_info.c" "notification_events.c" "i2c_bus.c" "ads1115.c" "gpio_inputs.c" "main.c" "mqtt_client.c" "userdb.c" "totp.c" "pn532_spi.c" "auth.c" "alarm_core.c" "web_server.c" "*.c")
file(GLOB MAIN_SRCS "*.c")

#set(MAIN_EMBED_TXTFILES
#    "certs/server_cert.pem"
#    "certs/server_key.pem"
##    "certs/broker_ca.pem"
#)
set(MAIN_EMBED_TXTFILES)

# Build/version metadata with Git-optional fallbacks
set(FW_VERSION "0.1.0" CACHE STRING "Firmware version")
string(TIMESTAMP BUILD_DATE "%Y-%m-%d" UTC)
string(TIMESTAMP BUILD_TIME "%H:%M:%S UTC" UTC)
find_package(Git QUIET)
if(GIT_FOUND)
    execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --short=12 HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_BRANCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    execute_process(COMMAND ${GIT_EXECUTABLE} diff --quiet
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        RESULT_VARIABLE GIT_DIFF_RESULT
        ERROR_QUIET)
endif()
if(NOT GIT_COMMIT)
    set(GIT_COMMIT "unknown")
endif()
if(NOT GIT_BRANCH)
    set(GIT_BRANCH "unknown")
endif()
if(NOT GIT_FOUND OR NOT DEFINED GIT_DIFF_RESULT)
    set(GIT_DIRTY "unknown")
elseif(GIT_DIFF_RESULT EQUAL 0)
    set(GIT_DIRTY "false")
else()
    set(GIT_DIRTY "true")
endif()


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
        app_update
        mdns
        esp_http_server
        esp_event
        esp_netif
        esp_eth
        esp_wifi
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
        # esp_https_server removed: we run plain HTTP server
        driver
    EMBED_TXTFILES
        ${MAIN_EMBED_TXTFILES}
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    CAN_TEST_BROADCAST=1
    FW_VERSION="${FW_VERSION}"
    BUILD_DATE="${BUILD_DATE}"
    BUILD_TIME="${BUILD_TIME}"
    GIT_COMMIT="${GIT_COMMIT}"
    GIT_BRANCH="${GIT_BRANCH}"
    GIT_DIRTY="${GIT_DIRTY}"
)

# Genera l’immagine SPIFFS dalla cartella spiffs/
spiffs_create_partition_image(spiffs ${CMAKE_SOURCE_DIR}/spiffs FLASH_IN_PROJECT)
add_custom_target(spiffs DEPENDS spiffs_spiffs_bin)