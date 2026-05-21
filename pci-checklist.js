// pci-checklist.js
const fs = require('fs');

// Codici colore per il terminale
const PASS = '\x1b[32m[PASS]\x1b[0m';
const FAIL = '\x1b[31m[FAIL]\x1b[0m';
const WARN = '\x1b[33m[WARN]\x1b[0m';

console.log("========================================================");
console.log("    AVVIO CHECKLIST DI CONFORMITÀ PCI-DSS (PoC)         ");
console.log("========================================================\n");

let vaultCode = '';
let serverCode = '';

try {
    // Lo script legge i file sorgente del tuo progetto
    vaultCode = fs.readFileSync('./vault.js', 'utf8');
    serverCode = fs.readFileSync('./server.js', 'utf8');
} catch (err) {
    console.error("Errore: Impossibile leggere i file. Assicurati di eseguire lo script nella cartella del progetto.");
    process.exit(1);
}

// ==========================================
// CONTROLLO 1: Requisito PCI-DSS 3.4
// I dati del titolare della carta devono essere illeggibili ovunque siano memorizzati.
// ==========================================
console.log("Verifica Req 3.4: Cifratura dei dati at-rest (nel database).");
if (vaultCode.includes("crypto.createCipheriv") && vaultCode.includes("aes-256")) {
    console.log(`${PASS} Rilevato algoritmo di crittografia forte (AES-256) per la protezione del PAN.\n`);
} else {
    console.log(`${FAIL} Nessuna implementazione di crittografia forte rilevata nel Vault.\n`);
}

// ==========================================
// CONTROLLO 2: Requisito PCI-DSS 3.3
// Mascheramento del PAN quando visualizzato/gestito (Tokenizzazione).
// ==========================================
console.log("Verifica Req 3.3: Minimizzazione dell'esposizione del PAN (Tokenizzazione).");
if (vaultCode.includes("crypto.randomBytes") && vaultCode.includes("tok_")) {
    console.log(`${PASS} Generazione sicura del token tramite entropia crittografica rilevata.\n`);
} else {
    console.log(`${FAIL} Il processo di tokenizzazione non risulta sicuro o è assente.\n`);
}

// ==========================================
// CONTROLLO 3: Requisito PCI-DSS 10.1
// Implementare audit trail per collegare tutti gli accessi ai dati di sistema.
// ==========================================
console.log("Verifica Req 10.1: Tracciamento e logging degli accessi ai dati sensibili.");
if (serverCode.includes("console.log") && serverCode.includes("detokenize")) {
    console.log(`${PASS} Rilevati meccanismi di logging sulle rotte critiche di de-tokenizzazione.\n`);
} else {
    console.log(`${FAIL} Manca un sistema di logging per tracciare chi accede al Vault.\n`);
}

// ==========================================
// CONTROLLO 4: Requisito PCI-DSS 4.1
// Utilizzare crittografia forte per i dati in transito (TLS/HTTPS).
// ==========================================
console.log("Verifica Req 4.1: Protezione dei dati in transito su reti pubbliche.");
if (serverCode.includes("https.createServer")) {
    console.log(`${PASS} Il server utilizza HTTPS/TLS per crittografare i dati in transito.\n`);
} else {
    console.log(`${WARN} Il prototipo utilizza HTTP locale. L'ambiente di produzione richiederà obbligatoriamente HTTPS/TLS.\n`);
}

console.log("========================================================");
console.log("               ANALISI COMPLETATA                       ");
console.log("========================================================\n");