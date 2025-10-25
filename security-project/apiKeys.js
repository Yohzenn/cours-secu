// ========================================
// MODULE DE GESTION DES API KEYS
// ========================================
const crypto = require("crypto");
const bcrypt = require("bcrypt");

// ========================================
// FONCTION : Générer une clé API unique
// ========================================
/**
 * Génère une clé API sécurisée avec préfixe
 * Format: sk_live_32caractères_aléatoires
 * @param {string} environment - 'live' ou 'test'
 * @returns {Object} - { key, prefix, hash }
 */
function generateApiKey(environment = "live") {
  // Générer 32 bytes aléatoires
  const randomBytes = crypto.randomBytes(32);

  // Convertir en base64 URL-safe
  const randomString = randomBytes
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "")
    .substring(0, 32);

  // Créer le préfixe (8 premiers caractères pour identification)
  const prefix = randomString.substring(0, 8);

  // Construire la clé complète
  const apiKey = `sk_${environment}_${randomString}`;

  return {
    key: apiKey, // La clé complète (à montrer UNE SEULE FOIS)
    prefix: `sk_${environment}_${prefix}...`, // Préfixe pour identification
    fullPrefix: `sk_${environment}_${prefix}`, // Pour recherche en DB
  };
}

// ========================================
// FONCTION : Hasher une clé API
// ========================================
/**
 * Hash une clé API avec bcrypt (comme un mot de passe)
 * @param {string} apiKey - La clé API en clair
 * @returns {Promise<string>} - Hash bcrypt
 */
async function hashApiKey(apiKey) {
  return await bcrypt.hash(apiKey, 10);
}

// ========================================
// FONCTION : Vérifier une clé API
// ========================================
/**
 * Vérifie si une clé API correspond à son hash
 * @param {string} apiKey - La clé API fournie
 * @param {string} hash - Le hash stocké en DB
 * @returns {Promise<boolean>} - True si valide
 */
async function verifyApiKey(apiKey, hash) {
  return await bcrypt.compare(apiKey, hash);
}

// ========================================
// FONCTION : Valider le format d'une clé API
// ========================================
/**
 * Vérifie que la clé API a le bon format
 * @param {string} apiKey - La clé à valider
 * @returns {boolean} - True si format valide
 */
function isValidApiKeyFormat(apiKey) {
  // Format attendu: sk_(live|test)_32caractères
  const regex = /^sk_(live|test)_[A-Za-z0-9\-_]{32}$/;
  return regex.test(apiKey);
}

// ========================================
// FONCTION : Extraire le préfixe d'une clé
// ========================================
/**
 * Extrait le préfixe d'une clé API pour recherche
 * @param {string} apiKey - La clé complète
 * @returns {string} - Le préfixe (ex: "sk_live_abc12345")
 */
function extractPrefix(apiKey) {
  if (!isValidApiKeyFormat(apiKey)) {
    return null;
  }

  // Extraire les 8 premiers caractères après sk_live_ ou sk_test_
  const parts = apiKey.split("_");
  if (parts.length >= 3) {
    const randomPart = parts[2];
    return `${parts[0]}_${parts[1]}_${randomPart.substring(0, 8)}`;
  }

  return null;
}

// ========================================
// FONCTION : Masquer une clé API
// ========================================
/**
 * Masque une clé API pour affichage sécurisé
 * @param {string} apiKey - La clé complète
 * @returns {string} - Clé masquée (ex: "sk_live_abc12345...")
 */
function maskApiKey(apiKey) {
  if (!apiKey) return "";

  const prefix = extractPrefix(apiKey);
  if (!prefix) return "****";

  return `${prefix}...`;
}

// ========================================
// EXPORTS
// ========================================
module.exports = {
  generateApiKey,
  hashApiKey,
  verifyApiKey,
  isValidApiKeyFormat,
  extractPrefix,
  maskApiKey,
};
