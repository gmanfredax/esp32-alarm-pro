# Centrale Allarme ESP32 — Full Build
- Stati: DISARMED, ARMED_HOME, ARMED_AWAY, ARMED_NIGHT, ARMED_CUSTOM, ALARM, MAINTENANCE
- Rete: Ethernet RMII (LAN8720)
- Bus: I²C GPIO33/32 → MCP23017 (Z1..Z12 + Tamper/Relay/LED), SPI PN532 (16/14/13/12), 1‑Wire DS18B20 su GPIO15
- Web UI: login (admin/user) + token sessione, 2FA TOTP opzionale
- MQTT: pubblicazione stato/zone, comandi arm/disarm
