// ========================================
// MODULE DE GESTION DES WEBHOOKS SHOPIFY
// ========================================
const crypto = require("crypto");

// ========================================
// FONCTION : Vérifier la signature HMAC Shopify
// ========================================
/**
 * Vérifie que le webhook provient bien de Shopify
 * Documentation: https://shopify.dev/docs/apps/webhooks/configuration/https#step-5-verify-the-webhook
 *
 * @param {string} body - Le corps brut de la requête (raw body)
 * @param {string} hmacHeader - La signature HMAC du header X-Shopify-Hmac-Sha256
 * @param {string} secret - Le secret webhook configuré dans Shopify
 * @returns {boolean} - True si signature valide
 */
function verifyShopifyWebhook(body, hmacHeader, secret) {
  if (!body || !hmacHeader || !secret) {
    return false;
  }

  // Calculer le HMAC du body avec le secret
  const hash = crypto
    .createHmac("sha256", secret)
    .update(body, "utf8")
    .digest("base64");

  // Comparer de manière sécurisée (protection contre timing attacks)
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(hmacHeader));
}

// ========================================
// FONCTION : Parser les produits d'une commande
// ========================================
/**
 * Extrait les produits et leurs quantités d'un webhook order/create
 * @param {Object} orderData - Le payload du webhook
 * @returns {Array} - [{shopify_id, quantity}, ...]
 */
function parseOrderProducts(orderData) {
  const products = [];

  if (!orderData.line_items || !Array.isArray(orderData.line_items)) {
    return products;
  }

  orderData.line_items.forEach((item) => {
    // Un line_item peut avoir plusieurs variantes du même produit
    if (item.product_id && item.quantity) {
      products.push({
        shopify_id: item.product_id,
        quantity: item.quantity,
        variant_id: item.variant_id,
        price: parseFloat(item.price) || 0,
        title: item.title || "Unknown Product",
      });
    }
  });

  return products;
}

// ========================================
// FONCTION : Valider le payload du webhook
// ========================================
/**
 * Vérifie que le webhook contient les données nécessaires
 * @param {Object} payload - Le payload du webhook
 * @param {string} eventType - Type d'événement attendu
 * @returns {Object} - {valid: boolean, error?: string}
 */
function validateWebhookPayload(payload, eventType) {
  if (!payload) {
    return { valid: false, error: "Payload vide" };
  }

  // Pour les webhooks order/create
  if (eventType === "orders/create") {
    if (!payload.id) {
      return { valid: false, error: "ID de commande manquant" };
    }
    if (!payload.line_items || !Array.isArray(payload.line_items)) {
      return { valid: false, error: "Line items manquants" };
    }
    if (payload.line_items.length === 0) {
      return { valid: false, error: "Aucun produit dans la commande" };
    }
  }

  return { valid: true };
}

// ========================================
// FONCTION : Extraire les métadonnées du webhook
// ========================================
/**
 * Extrait des informations utiles du webhook pour logging
 * @param {Object} payload - Le payload du webhook
 * @returns {Object} - Métadonnées utiles
 */
function extractWebhookMetadata(payload) {
  return {
    shopify_order_id: payload.id,
    order_number: payload.order_number,
    customer_email: payload.email || payload.customer?.email,
    total_price: payload.total_price,
    currency: payload.currency,
    created_at: payload.created_at,
    financial_status: payload.financial_status,
    fulfillment_status: payload.fulfillment_status,
    items_count: payload.line_items?.length || 0,
  };
}

// ========================================
// EXPORTS
// ========================================
module.exports = {
  verifyShopifyWebhook,
  parseOrderProducts,
  validateWebhookPayload,
  extractWebhookMetadata,
};
