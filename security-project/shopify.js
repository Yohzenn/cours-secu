// ========================================
// MODULE SHOPIFY API
// ========================================
const axios = require("axios");

// Configuration de base pour les requêtes Shopify
const shopifyAPI = axios.create({
  baseURL: `https://${process.env.SHOPIFY_STORE_URL}/admin/api/${process.env.SHOPIFY_API_VERSION}`,
  headers: {
    "X-Shopify-Access-Token": process.env.SHOPIFY_ACCESS_TOKEN,
    "Content-Type": "application/json",
  },
});

// ========================================
// FONCTION : Créer un produit dans Shopify
// ========================================
/**
 * Crée un produit dans Shopify
 * @param {string} title - Nom du produit
 * @param {number} price - Prix du produit
 * @returns {Promise<Object>} - Données du produit créé
 */
async function createShopifyProduct(title, price) {
  try {
    // Structure du produit selon l'API Shopify
    const productData = {
      product: {
        title: title,
        body_html: `<p>Produit créé via l'API de sécurité</p>`,
        vendor: "Security Project",
        product_type: "API Product",
        status: "active",
        variants: [
          {
            price: price.toString(),
            inventory_management: null, // Pas de gestion de stock
            inventory_policy: "continue", // Permettre les commandes même si rupture
          },
        ],
      },
    };

    // Appel API POST vers Shopify
    const response = await shopifyAPI.post("/products.json", productData);

    // Retourner les données importantes
    return {
      success: true,
      shopify_id: response.data.product.id,
      title: response.data.product.title,
      price: response.data.product.variants[0].price,
      shopify_url: `https://${process.env.SHOPIFY_STORE_URL}/admin/products/${response.data.product.id}`,
      raw_data: response.data.product,
    };
  } catch (error) {
    console.error("Erreur Shopify API:", error.response?.data || error.message);

    // Gérer les erreurs spécifiques de Shopify
    if (error.response?.status === 401) {
      throw new Error("Token Shopify invalide ou expiré");
    } else if (error.response?.status === 422) {
      throw new Error(
        "Données invalides: " + JSON.stringify(error.response.data.errors)
      );
    } else {
      throw new Error("Erreur lors de la création du produit Shopify");
    }
  }
}

// ========================================
// FONCTION : Récupérer un produit Shopify
// ========================================
/**
 * Récupère les détails d'un produit depuis Shopify
 * @param {string|number} shopifyId - ID du produit dans Shopify
 * @returns {Promise<Object>} - Données du produit
 */
async function getShopifyProduct(shopifyId) {
  try {
    const response = await shopifyAPI.get(`/products/${shopifyId}.json`);

    return {
      success: true,
      shopify_id: response.data.product.id,
      title: response.data.product.title,
      price: response.data.product.variants[0]?.price || 0,
      status: response.data.product.status,
      raw_data: response.data.product,
    };
  } catch (error) {
    if (error.response?.status === 404) {
      throw new Error("Produit non trouvé dans Shopify");
    }
    throw new Error("Erreur lors de la récupération du produit");
  }
}

// ========================================
// FONCTION : Mettre à jour un produit Shopify
// ========================================
/**
 * Met à jour un produit dans Shopify
 * @param {string|number} shopifyId - ID du produit dans Shopify
 * @param {Object} updates - Champs à mettre à jour {title, price}
 * @returns {Promise<Object>} - Données du produit mis à jour
 */
async function updateShopifyProduct(shopifyId, updates) {
  try {
    const productData = {
      product: {},
    };

    // Ajouter les champs à mettre à jour
    if (updates.title) {
      productData.product.title = updates.title;
    }

    if (updates.price) {
      // Récupérer le variant ID (nécessaire pour modifier le prix)
      const product = await getShopifyProduct(shopifyId);
      const variantId = product.raw_data.variants[0].id;

      // Mise à jour du variant séparément
      await shopifyAPI.put(`/variants/${variantId}.json`, {
        variant: {
          price: updates.price.toString(),
        },
      });
    }

    // Si on met à jour le titre
    if (updates.title) {
      await shopifyAPI.put(`/products/${shopifyId}.json`, productData);
    }

    return {
      success: true,
      message: "Produit mis à jour avec succès",
    };
  } catch (error) {
    console.error(
      "Erreur mise à jour Shopify:",
      error.response?.data || error.message
    );
    throw new Error("Erreur lors de la mise à jour du produit");
  }
}

// ========================================
// FONCTION : Supprimer un produit Shopify
// ========================================
/**
 * Supprime un produit de Shopify
 * @param {string|number} shopifyId - ID du produit dans Shopify
 * @returns {Promise<Object>} - Confirmation de suppression
 */
async function deleteShopifyProduct(shopifyId) {
  try {
    await shopifyAPI.delete(`/products/${shopifyId}.json`);

    return {
      success: true,
      message: "Produit supprimé de Shopify avec succès",
    };
  } catch (error) {
    if (error.response?.status === 404) {
      // Le produit n'existe plus dans Shopify, considérer comme un succès
      return {
        success: true,
        message: "Produit déjà supprimé de Shopify",
      };
    }
    throw new Error("Erreur lors de la suppression du produit");
  }
}

// ========================================
// EXPORTS
// ========================================
module.exports = {
  createShopifyProduct,
  getShopifyProduct,
  updateShopifyProduct,
  deleteShopifyProduct,
};
