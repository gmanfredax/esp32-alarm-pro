window.APP_CONFIG = window.APP_CONFIG || {};

window.APP_CONFIG.wizard = Object.assign({
  enabled: true,
  autoShow: true,
  alwaysShow: false,
  storageKey: 'alarmpro_wizard_v1',
  fallbackDelayMs: 3500,
  reopenSelector: '[data-act="wizard"]',
  prevLabel: 'Indietro',
  nextLabel: 'Avanti',
  doneLabel: 'Inizia a usare Alarm Pro',
  skipLabel: 'Ricordamelo dopo',
  steps: [
    {
      icon: '👋',
      title: 'Benvenuto in Alarm Pro',
      description: 'Una breve guida per completare la messa in servizio della centrale.',
      bullets: [
        'Verifica che data e ora della scheda siano corrette.',
        'Controlla il cablaggio delle zone e assegna un nome riconoscibile.',
        'Decidi quali scenari (Home, Night, Custom) utilizzare con i relativi sensori.'
      ]
    },
    {
      icon: '🛡️',
      title: 'Configura gli utenti',
      description: 'Dalla voce “Impostazioni utente” puoi creare gli operatori e proteggerli con più fattori.',
      bullets: [
        'Imposta PIN e badge RFID per ogni persona autorizzata.',
        'Abilita la 2FA TOTP sugli account amministrativi e salva i codici di recupero.',
        'Rigenera i token API se utilizzi integrazioni esterne o automazioni.'
      ]
    },
    {
      icon: '⚙️',
      title: 'Personalizza il sistema',
      description: 'Rivedi le impostazioni di rete, MQTT e certificato HTTPS prima di andare in produzione.',
      bullets: [
        'Compila la sezione “Impostazioni sistema” per rete ed MQTT.',
        'Carica un certificato HTTPS personale per l’accesso remoto in sicurezza.',
        'Esegui una prova di arm/disarm e verifica sirene, relè ed eventuali scenari automatici.'
      ],
      doneLabel: 'Tutto chiaro'
    }
  ]
}, window.APP_CONFIG.wizard || {});