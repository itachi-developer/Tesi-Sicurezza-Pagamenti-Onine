const crypto = require('crypto');

// PCI-DSS: Simulazione di una chiave derivata sicura (PBKDF2/scrypt) o variabile d'ambiente.
// In produzione verrebbe gestita tramite HSM (Hardware Security Module).
const ENCRYPTION_KEY = process.env.MASTER_KEY 
    ? Buffer.from(process.env.MASTER_KEY, 'hex') 
    : crypto.scryptSync('master-password-super-sicura', 'salt-univoco', 32);

const IV_LENGTH = 16;
const tokenDatabase = new Map();

/**
 * Funzione interna per crittografare il PAN (Requisito PCI-DSS: dati at-rest cifrati)
 */
function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    // Salva l'IV insieme al testo cifrato separati da ':', necessario per la decrittografia
    return iv.toString('hex') + ':' + encrypted;
}

/**
 * Funzione interna per decrittografare il PAN (detokenizzazione controllata)
 */
function decrypt(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = textParts.join(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

/**
 * Riceve un PAN, lo cifra, lo salva nel Vault e restituisce un Token univoco.
 */
function tokenizePAN(pan) {
    // 1. Genera un Token casuale (formato: tok_ + stringa alfanumerica di 16 caratteri)
    const token = 'tok_' + crypto.randomBytes(8).toString('hex');
    
    // 2. Cifra il dato sensibile
    const encryptedPAN = encrypt(pan);
    
    // 3. Memorizza nel database simulato la relazione Token -> PAN cifrato
    tokenDatabase.set(token, encryptedPAN);
    
    return token;
}

/**
 * Riceve un Token e, se valido, restituisce il PAN originale decifrato.
 */
function detokenize(token) {
    const encryptedPAN = tokenDatabase.get(token);
    
    if (!encryptedPAN) {
        throw new Error('Token non valido o inesistente nel Vault');
    }
    
    // Decifra e restituisce il dato
    return decrypt(encryptedPAN);
}

// Esporta le funzioni per poterle usare nel server
module.exports = {
    tokenizePAN,
    detokenize
};
