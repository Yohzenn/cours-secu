// ========================================
// MIDDLEWARE D'AUTHENTIFICATION UNIFIÉ
// Supporte JWT (Authorization) et API Key (x-api-key)
// ========================================
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");
const { verifyApiKey, isValidApiKeyFormat } = require("./apiKeys");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// ========================================
// MIDDLEWARE : Authentification JWT
// ========================================
async function authenticateJWT(req, res, next) {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Token JWT manquant" });
    }

    // Vérifier et décoder le token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Récupérer l'utilisateur avec son rôle
    const { data: user, error } = await supabase
      .from("users")
      .select(
        `
        id,
        nom,
        email,
        password_changed_at,
        created_at,
        role_id,
        roles (
          nom,
          can_post_login,
          can_get_my_user,
          can_get_users,
          can_post_products,
          can_upload_product_image,
          can_get_bestsellers
        )
      `
      )
      .eq("id", decoded.userId)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: "Utilisateur non trouvé" });
    }

    // Vérifier si le mot de passe a été changé après l'émission du token
    const passwordChangedAt = new Date(user.password_changed_at).getTime();
    const tokenIssuedAt = decoded.iat * 1000;

    if (passwordChangedAt > tokenIssuedAt) {
      return res.status(401).json({
        error: "Token expiré suite au changement de mot de passe",
      });
    }

    // Ajouter l'utilisateur à la requête
    req.user = {
      id: user.id,
      nom: user.nom,
      email: user.email,
      role: user.roles,
      authMethod: "jwt",
    };

    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token expiré" });
    }
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Token invalide" });
    }
    console.error("Erreur authentification JWT:", error);
    res.status(500).json({ error: "Erreur serveur" });
  }
}

// ========================================
// MIDDLEWARE : Authentification API Key
// ========================================
async function authenticateApiKey(req, res, next) {
  try {
    const apiKey = req.headers["x-api-key"];

    if (!apiKey) {
      return res.status(401).json({ error: "Clé API manquante" });
    }

    // Vérifier le format de la clé
    if (!isValidApiKeyFormat(apiKey)) {
      return res.status(401).json({ error: "Format de clé API invalide" });
    }

    // Récupérer toutes les clés actives (on ne peut pas rechercher par hash directement)
    const { data: apiKeys, error } = await supabase
      .from("api_keys")
      .select(
        `
        id,
        key_hash,
        name,
        user_id,
        is_active,
        usage_count,
        users (
          id,
          nom,
          email,
          roles (
            nom,
            can_post_login,
            can_get_my_user,
            can_get_users,
            can_post_products,
            can_upload_product_image,
            can_get_bestsellers
          )
        )
      `
      )
      .eq("is_active", true);

    if (error || !apiKeys || apiKeys.length === 0) {
      return res.status(401).json({ error: "Clé API invalide" });
    }

    // Vérifier la clé contre tous les hashs
    let validKey = null;
    for (const key of apiKeys) {
      const isValid = await verifyApiKey(apiKey, key.key_hash);
      if (isValid) {
        validKey = key;
        break;
      }
    }

    if (!validKey) {
      return res.status(401).json({ error: "Clé API invalide" });
    }

    // Mettre à jour last_used_at et usage_count
    await supabase
      .from("api_keys")
      .update({
        last_used_at: new Date().toISOString(),
        usage_count: validKey.usage_count + 1,
      })
      .eq("id", validKey.id);

    // Ajouter l'utilisateur à la requête
    req.user = {
      id: validKey.users.id,
      nom: validKey.users.nom,
      email: validKey.users.email,
      role: validKey.users.roles,
      authMethod: "apikey",
      apiKeyName: validKey.name,
    };

    next();
  } catch (error) {
    console.error("Erreur authentification API Key:", error);
    res.status(500).json({ error: "Erreur serveur" });
  }
}

// ========================================
// MIDDLEWARE : Authentification unifiée (JWT OU API Key)
// ========================================
async function authenticate(req, res, next) {
  // Priorité : vérifier d'abord si une API Key est fournie
  const apiKey = req.headers["x-api-key"];
  const authHeader = req.headers["authorization"];

  if (apiKey) {
    // Authentification par API Key
    return authenticateApiKey(req, res, next);
  } else if (authHeader) {
    // Authentification par JWT
    return authenticateJWT(req, res, next);
  } else {
    return res.status(401).json({
      error:
        "Authentification requise (JWT via Authorization ou API Key via x-api-key)",
    });
  }
}

// ========================================
// MIDDLEWARE : Vérification des permissions
// ========================================
function checkPermission(permissionName) {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(403).json({ error: "Permissions non disponibles" });
    }

    if (!req.user.role[permissionName]) {
      return res.status(403).json({
        error: `Permission refusée: ${permissionName} requis`,
      });
    }

    next();
  };
}

// ========================================
// EXPORTS
// ========================================
module.exports = {
  authenticateJWT,
  authenticateApiKey,
  authenticate,
  checkPermission,
};
