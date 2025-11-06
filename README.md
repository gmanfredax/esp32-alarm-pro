# NSAlarmPro – Centrale ESP32

Questo documento descrive il funzionamento della **centrale NSAlarmPro** basata su **ESP32-WROOM-32D-N16** e l’architettura generale del firmware.

> Nella terminologia del progetto:
> - **Centrale** = ESP32 (board principale, rete, MQTT, CAN, logica allarme).
> - **Nodi** = periferiche su bus CAN (STM32, espansioni zone/uscite, ecc.).

---

## 1. Panoramica

La centrale NSAlarmPro è un sistema di allarme modulare con queste funzioni principali:

- Gestione di **zone locali** (ingressi direttamente collegati alla centrale).
- Gestione di **zone remote** tramite **nodi su bus CAN**.
- Controllo di **uscite programmabili** (sirene, relay, segnalazioni, ecc.).
- Gestione di **stati di inserimento/disinserimento** (Totale, Parziale/Notte, Tecnico, ecc.).
- Interfaccia di comunicazione:
  - **Ethernet** (o Wi-Fi, se abilitato).
  - **MQTT** verso broker esterno (EMQX, ecc.).
  - **Web server** locale per configurazione e diagnostica.
- Integrabile con **tastiere, lettori RFID (PN532)** e altre periferiche.

---

## 2. Architettura hardware (centrale)

Componenti principali:

- **MCU**: ESP32-WROOM-32D-N16
  - 2 core a 240 MHz
  - Flash esterna 16 MB
- **Rete**:
  - Interfaccia Ethernet (es. LAN8720 o W5500) collegata all’ESP32.
- **Bus di campo**:
  - **CAN bus** per collegare i nodi remoti (STM32, espansioni).
- **Ingressi / Zone locali**:
  - Linee dedicate per zone tradizionali (EOL/2EOL/3EOL) e/o ingressi digitali.
  - Possibile uso di ADC esterni (es. ADS1115) o expander I/O (es. MCP23017) a seconda della revisione hardware.
- **Uscite**:
  - Uscita sirena/e.
  - Uscite programmabili (relay, open collector, LED, ecc.).
- **Alimentazione**:
  - Ingresso 12 V.
  - Monitoraggio linea alimentatore e batteria (soglie di batteria bassa, mancanza rete, ecc.).
- **Periferiche utente**:
  - PN532 per lettori RFID (tessere, tag).
  - LED di stato, buzzer su centrale, eventuali pulsanti locali.

---

## 3. Architettura firmware (moduli principali)

Il firmware è basato su **ESP-IDF** (FreeRTOS) e suddiviso in moduli:

- `main.c`
  - Inizializzazione di base (NVS, log, pin, watchdog).
  - Avvio dei task principali.
- `zone_local.c`
  - Gestione delle **zone locali** (acquisizione, filtraggio, mappa tensione → stato).
- `can_bus.c`
  - Driver e logica di comunicazione con i **nodi CAN**.
  - Discovery, heartbeat, sincronizzazione stato zone/uscite remote.
- `web_server.c`
  - Web server HTTP/HTTPS.
  - API REST per configurazione e diagnostica.
  - Pagine statiche del wizard locale.
- (Altri moduli tipici, a seconda del progetto)
  - `mqtt_client.c` / `mqtt_manager.c`: integrazione con broker MQTT.
  - `alarm_core.c` / `alarm_logic.c`: logica di allarme, gestione stati di inserimento.
  - `config_store.c`: salvataggio e caricamento configurazione (NVS/flash).
  - `rfid.c`: gestione lettore PN532 se presente.

Ogni modulo espone API chiare e comunica tramite code/eventi FreeRTOS o strutture dati condivise protette da mutex.

---

## 4. Flusso di boot

1. **Reset / Power-on**
   - Inizializzazione log (UART, livello di debug).
   - Inizializzazione NVS e lettura configurazione.
   - Inizializzazione GPIO, ADC, bus I2C/SPI, CAN, Ethernet.
2. **Configurazione di rete**
   - Configurazione Ethernet (DHCP o IP statico).
   - Avvio stack TCP/IP.
3. **Avvio servizi di comunicazione**
   - Avvio di **MQTT client** (se configurato e server raggiungibile).
   - Avvio di **web server HTTP/HTTPS**.
4. **Avvio logica di allarme**
   - Creazione task di scansione zone.
   - Creazione task CAN per nodi remoti.
   - Inizializzazione stati di inserimento (default: Disinserito).
5. **Loop operativo**
   - Lettura continua delle zone (locali e remote).
   - Aggiornamento stato uscite.
   - Gestione eventi (allarme, tamper, guasti) con notifiche locali, CAN, MQTT.

---

## 5. Gestione zone

### 5.1 Tipologie di zona

Ogni zona (locale o remota) è configurabile con:

- **Tipo di ingresso**:
  - Contatto NC / NO.
  - **EOL / 2EOL / 3EOL** (resistenze di fine linea).
- **Ruolo logico**:
  - Istantanea (perimetro).
  - Ritardata ingresso/uscita.
  - 24H (antipanico, antincendio, tecnica).
  - Escludibile / forzabile / mascherabile.

### 5.2 Stati di zona

Stati logici tipici:

- **Riposo** (normale).
- **Allarme** (variazione ingresso su zona attiva).
- **Tamper** (manomissione, corto/aperto anomalo).
- **Guasto** (mancanza alimentazione nodo, ADC fuori range, ecc.).

### 5.3 Scansione e filtraggio

La centrale effettua:

- **Campionamento periodico** delle zone (frequenza configurabile).
- **Filtraggio e antirimbalzo**:
  - Tempo minimo di permanenza in stato di allarme prima di confermare l’evento.
  - Finestra di media/filtraggio per ingressi analogici (EOL/2EOL/3EOL).
- **Mappatura tensione → stato** (per zone bilanciate):
  - Range VOLT → Riposo.
  - Range VOLT → Allarme.
  - Range VOLT → Tamper.
  - Range VOLT → Guasto/corto circuito.

---

## 6. Logica di allarme (Alarm Core)

### 6.1 Stati di inserimento

La centrale gestisce almeno:

- **Disinserito**
- **Inserito Totale**
- **Inserito Parziale / Notte / Perimetrale**
- **Stato Tecnico** (manutenzione, test, programmazione)

Ogni stato definisce quali zone sono:

- Attive
- Escluse
- Ritardate

### 6.2 Temporizzazioni

Parametri tipici:

- **Tempo di ingresso**: ritardo prima di attivare la sirena se una zona ritardata entra in allarme a centrale inserita.
- **Tempo di uscita**: ritardo tra il comando di inserimento e l’effettivo inserimento.
- **Tempo sirena**: durata massima della sirena in caso di allarme.

### 6.3 Gestione eventi

In caso di **evento di zona**:

1. La zona cambia stato (es. Riposo → Allarme).
2. `alarm_core` verifica:
   - Stato di inserimento.
   - Tipo zona.
   - Eventuali esclusioni / inibizioni.
3. Se l’evento è valido:
   - Attiva **uscite di allarme** (sirene, relay).
   - Genera **log evento**.
   - Propaga l’evento:
     - Verso nodi CAN interessati.
     - Verso MQTT.
     - Verso interfacce utente locali (web, tastiera, LED).

---

## 7. Nodi CAN e zone remote

### 7.1 Scopo del bus CAN

Il bus CAN è usato per:

- Espandere il numero di zone / uscite.
- Collegare moduli periferici (tastiere, moduli I/O tecnici, ecc.).
- Mantenere un bus robusto e adatto ad ambiente “antintrusione”.

### 7.2 Funzioni principali del modulo `can_bus`

- **Inizializzazione** periferica CAN (bitrate, filtri).
- **Heartbeat**:
  - Ogni nodo invia periodicamente un messaggio di presenza.
  - La centrale tiene traccia dell’**online/offline** di ogni nodo.
- **Sincronizzazione configurazione**:
  - La centrale può inviare ai nodi:
    - Assegnazione ID di zona.
    - Parametri di soglia / filtraggio (a seconda delle capacità del nodo).
- **Scambio eventi**:
  - Nodi → Centrale: stato zone/uscite remote, eventi di allarme/tamper, diagnostica.
  - Centrale → Nodi: comandi per attivare uscite, aggiornare LED, display, ecc.

---

## 8. Integrazione MQTT

La centrale si connette a un broker MQTT (es. EMQX) e pubblica/sottoscrive vari **topic**:

> I nomi esatti dei topic possono variare a seconda della configurazione del progetto; di seguito uno schema tipico.

- **Stato centrale**  
  `nsalarmpro/<id_centrale>/status` 
  - Online/Offline.
  - Stato inserimento (disinserito, totale, parziale).
  - Stato alimentazioni (rete, batteria).

- **Eventi di zona**  
  `nsalarmpro/<id_centrale>/zone/<zone_id>/event`  
  Payload tipico:
  ```json
  {
    "zone": 5,
    "state": "alarm",
    "type": "perimeter",
    "timestamp": 1731000000
  }

- **Comandi remoti**
  `nsalarmpro/<id_centrale>/cmd`
  - Inserisci/disinserisci.
  - Escludi zona.
  - Richiedi reboot.
  - Modalità tecnica, ecc.

- **Provisioning / Claim**
  - Topic dedicati al meccanismo di claim con il sistema di provisioning (associazione tra dispositivo fisico e account remoto).

Lato firmware:
Il task MQTT:
- Mantiene la connessione verso il broker.
- Ritenta la connessione con backoff in caso di errore.
- Gestisce le callback di sottoscrizione (comandi ricevuti).
- Pubblica periodicamente lo stato e gli eventi.

---

## 9. Web server locale
Il modulo web_server.c espone:

UI HTTP/HTTPS:
  - Wizard di prima configurazione.
  - Pagine di configurazione (zone, uscite, rete, MQTT, CAN, utenti).
  - Pagine di diagnostica (log recenti, stato nodi, test zone/uscite).

API REST (tipicamente sotto /api/...):
  - GET /api/status → stato generale della centrale.
  - GET /api/zones → elenco zone e stato.
  - POST /api/zones/<id> → modifica configurazione zona.
  - POST /api/command → comandi (inserimento, disinserimento, reset allarmi, ecc.).

In modalità protetta, il server gira in HTTPS con certificato configurato nel firmware o derivato dalla configurazione.

---

## 10. Configurazione e storage
La configurazione è salvata in una partizione di flash (NVS o custom), ad esempio:
  - Parametri di rete.
  - Parametri MQTT (host, porta, credenziali, topic base).
  - Mappatura zone locali e remote.
  - Parametri logica di allarme (tempi, tipi zone, comportamenti).
  - Utenti/autorizzazioni (PIN, RFID, ecc., se gestiti in centrale).

Operazioni tipiche:
  - Caricamento all’avvio: lettura da NVS/partizione.
  - Salvataggio on change: alla modifica da web/API/MQTT, i parametri vengono salvati in modo atomico (per evitare corruzioni in caso di power loss).
  - Reset configurazione: possibilità di riportare la centrale a uno stato di fabbrica (config di default).

---

## 11. Logging e diagnostica
La centrale fornisce diversi livelli di diagnostica:
  - Log su seriale (UART, ESP_LOGx) per sviluppo.
  - Log su MQTT (se abilitato) su topic di debug/diagnostica.
  - Log su web UI:
  - Visualizzazione ultimi eventi di allarme.
  - Log di sistema (boot, errori CAN, errori MQTT, reboot inattesi).

Watchdog:
  - Hardware e/o software watchdog per reset automatico in caso di blocchi.

---

## 12. Flusso tipico di utilizzo
1. Alimentazione della centrale → boot, inizializzazione, connessione rete.
2. L’utente accede al web server locale oppure tramite sistema di provisioning:
  - Imposta rete, MQTT, parametri base.
  - Configura zone, uscite, utenti.
3. I nodi CAN vengono rilevati e associati a zone/uscite tramite UI.
4. La centrale passa in stato operativo:
  - Cicli di scansione zone.
  - Monitoraggio nodi CAN.
  - Pubblicazione stato su MQTT.
5. In caso di allarme:
  - Attivazione uscite sirena.
  - Pubblicazione evento su MQTT.
  - Log su web UI / seriale.

---

## 13. Note per lo sviluppo
  - Il progetto è pensato per ESP-IDF (versione definita in CMakeLists.txt/idf.py).
  - Target: esp32 (CONFIG_IDF_TARGET="esp32").
  - Dimensione flash: 16 MB, modalità QIO 40 MHz (sdkconfig.defaults).
  - La configurazione specifica di pin e periferiche è centralizzata in un file tipo pins.h per semplificare la manutenzione hardware.

----------

Per contributi o modifiche è consigliato:
  - Lavorare su branch wip/....
  - Unire periodicamente su branch di sviluppo (canbus, develop, ecc.).
  - Tenere main riservato a versioni ritenute stabili.