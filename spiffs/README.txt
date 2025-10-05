ESP32 HTTPS Web — SPIFFS assets & certificate
=============================================

Cosa contiene questa cartella:
- spiffs/www/index.html, style.css, script.js   → file statici serviti dal server
- spiffs/cert.pem, spiffs/key.pem               → segnaposto (sostituiscili con PEM reali)

Genera certificato self‑signed ECDSA P‑256 (10 anni):
----------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -days 3650 -subj "/CN=esp32.local" -out cert.pem

Poi copia i PEM nella cartella spiffs/ (sovrascrivendo i segnaposto) e ricompila:
-------------------------------------------------------------------------------
idf.py -p /dev/ttyUSB0 build flash monitor

Note:
- Il codice carica i PEM da: /spiffs/cert.pem e /spiffs/key.pem
- L'immagine SPIFFS viene generata da CMake con spiffs_create_partition_image
- Assicurati che la tua partitions.csv includa una partizione 'spiffs' abbastanza grande
