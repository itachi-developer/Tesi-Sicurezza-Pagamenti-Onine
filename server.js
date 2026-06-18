// server.js
const express = require('express');
const crypto = require('crypto');
const { tokenizePAN, detokenize } = require('./vault');
const transactions = new Map(); // Store temporaneo per i pagamenti in corso
const app = express();
const PORT = 3000;

// Middleware per permettere ad Express di leggere i dati in formato JSON
app.use(express.json());

// Middleware per la sicurezza lato client (PCI-DSS v4.0 Req 6.4.3)
// Imposta una Content Security Policy base per bloccare script non autorizzati
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'");
    next();
});

/**
 * ENDPOINT 1: Tokenizzazione
 * Il client invia il PAN, il server risponde con il Token.
 */
app.post('/api/tokenize', (req, res) => {
    // AGGIUNTO || {} per evitare il crash se req.body è undefined
    const { pan } = req.body || {};

    if (!pan) {
        return res.status(400).json({ error: "PAN mancante nella richiesta" });
    }

    try {
        const token = tokenizePAN(pan);
        console.log(`[VAULT] PAN tokenizzato. Generato token: ${token}`);
        
        res.status(200).json({
            status: "success",
            message: "Dati sensibili salvati in sicurezza",
            token: token
        });
    } catch (error) {
        res.status(500).json({ error: "Errore interno del Vault" });
    }
});

/**
 * ENDPOINT 2: De-tokenizzazione controllata
 * Usato (ad esempio dal gateway) per recuperare il PAN.
 * PROTETTO tramite API Key interna (PCI-DSS Least Privilege).
 */
app.post('/api/detokenize', (req, res) => {
    // Controllo degli accessi Server-to-Server
    const internalApiKey = req.headers['x-internal-api-key'];
    
    if (!internalApiKey || internalApiKey !== 'poc-internal-secret-2026') {
        console.warn(`[SECURITY] Tentativo di de-tokenizzazione non autorizzato!`);
        return res.status(401).json({ error: "Accesso negato: API Key interna mancante o non valida" });
    }

    const { token } = req.body || {};


    if (!token) {
        return res.status(400).json({ error: "Token mancante nella richiesta" });
    }

    try {
        const panOriginale = detokenize(token);
        console.log(`[VAULT] De-tokenizzazione autorizzata ed effettuata per il token: ${token}`);
        
        res.status(200).json({
            status: "success",
            pan: panOriginale
        });
    } catch (error) {
        res.status(404).json({ error: error.message });
    }
});

/**
 * MODULO 2: Elaborazione Pagamento con logica 3DS2 (SCA)
 * Riceve il token e l'importo, decide se fare Challenge o Frictionless.
 */
app.post('/api/process-payment', (req, res) => {
    const { token, amount, currency } = req.body || {};

    if (!token || !amount) {
        return res.status(400).json({ error: "Dati incompleti" });
    }

    const transactionId = 'tx_' + crypto.randomBytes(4).toString('hex');

    // LOGICA DI RISCHIO (RBA - Risk Based Authentication)
    // Sotto i 30 euro simuliamo il flusso "Frictionless" (niente SCA)
    if (amount <= 30) {
        console.log(`[3DS2] Transazione ${transactionId} - Flusso Frictionless applicato.`);
        return res.status(200).json({
            status: "success",
            transactionId: transactionId,
            method: "frictionless",
            message: "Pagamento autorizzato con successo."
        });
    } 

    // Sopra i 30 euro simuliamo il flusso "Challenge" (Richiesta SCA)
    console.log(`[3DS2] Transazione ${transactionId} - Importo elevato (${amount}). Richiesta Challenge (SCA).`);
    
    // Salva lo stato "PENDING" nel database simulato
    transactions.set(transactionId, {
        token: token,
        amount: amount,
        status: 'pending_sca'
    });

    res.status(202).json({
        status: "action_required",
        transactionId: transactionId,
        method: "challenge",
        acsUrl: `http://localhost:3000/mock-acs/${transactionId}`, // URL simulato della banca
        message: "Autenticazione forte richiesta dall'istituto emittente."
    });
});

/**
 * MODULO 2: Simulazione dell'ACS (Access Control Server) della Banca
 * Questo endpoint "conferma" che l'utente ha inserito l'OTP correttamente.
 */
app.post('/api/verify-sca', (req, res) => {
    const { transactionId, otp } = req.body;

    const tx = transactions.get(transactionId);

    if (!tx) {
        return res.status(404).json({ error: "Transazione non trovata" });
    }

    // Simula che l'OTP corretto sia sempre '1234'
    if (otp === '1234') {
        tx.status = 'completed';
        console.log(`[3DS2] Challenge superata per ${transactionId}. Pagamento completato.`);
        
        // Qui nella realtà chiameremmo il Modulo 1 detokenize() per mandare i dati alla banca
        res.status(200).json({
            status: "success",
            message: "SCA completata. Pagamento autorizzato."
        });
    } else {
        tx.status = 'failed';
        console.log(`[3DS2] SCA Fallita per ${transactionId}. OTP errato.`);
        res.status(401).json({
            status: "failed",
            error: "Codice OTP errato. Transazione negata."
        });
    }
});

// Avvio del server
app.listen(PORT, () => {
    console.log(`Gateway di Pagamento simulato in esecuzione sulla porta ${PORT}`);
    console.log(`Pronto per gestire tokenizzazione e detokenizzazione...`);
});
