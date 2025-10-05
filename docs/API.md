GET  /api/status
GET  /api/zones
POST /api/arm   { "mode": "home|away|night|custom" }
POST /api/disarm {}
POST /api/login { "user":"", "pass":"", "otp":"optional" }
GET  /api/logs
POST /api/outputs { "relay":0|1, "led_state":0|1, "led_maint":0|1 }
