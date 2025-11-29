file(GLOB MAIN_SRCS "*.c")

idf_component_register(
    SRCS
        "main.c"
        "expansion_node.c"
        "can_bus_protocol.c"
        # "oneshot_read_main.c"
    INCLUDE_DIRS
        "."
    REQUIRES
        esp_event
        esp_timer
        esp_system
        spiffs
        nvs_flash
        esp_adc
    PRIV_REQUIRES
        driver
)
