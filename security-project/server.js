// ========================================
// IMPORTS ET CONFIGURATION
// ========================================
require("dotenv").config();
const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { createShopifyProduct, getShopifyProduct } = require("./shopify");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Initialiser Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// ========================================
// RATE LIMITING - 1 tentative toutes les 5 secondes
// ========================================
const loginLimiter = rateLimit({
  windowMs: 5 * 1000, // 5 secondes
  max: 1, // 1 requête par fenêtre
  message: {
    error: "Trop de tentatives de connexion. Réessayez dans 5 secondes.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// ========================================
// MIDDLEWARE D'AUTHENTIFICATION
// ========================================
async function authenticateToken(req, res, next) {
  try {
    // 1. Récupérer le token du header Authorization
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Format: "Bearer TOKEN"

    if (!token) {
      return res.status(401).json({ error: "Token manquant" });
    }

    // 2. Vérifier et décoder le token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 3. Récupérer l'utilisateur avec son rôle
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
          can_post_products
        )
      `
      )
      .eq("id", decoded.userId)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: "Utilisateur non trouvé" });
    }

    // 4. Vérifier si le mot de passe a été changé après l'émission du token
    const passwordChangedAt = new Date(user.password_changed_at).getTime();
    const tokenIssuedAt = decoded.iat * 1000; // Convertir en millisecondes

    if (passwordChangedAt > tokenIssuedAt) {
      return res.status(401).json({
        error: "Token expiré suite au changement de mot de passe",
      });
    }

    // 5. Ajouter l'utilisateur et ses permissions à la requête
    req.user = {
      id: user.id,
      nom: user.nom,
      email: user.email,
      role: user.roles,
    };

    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token expiré" });
    }
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Token invalide" });
    }
    console.error("Erreur authentification:", error);
    res.status(500).json({ error: "Erreur serveur" });
  }
}

// ========================================
// MIDDLEWARE DE VÉRIFICATION DES PERMISSIONS
// ========================================
function checkPermission(permissionName) {
  return (req, res, next) => {
    // L'utilisateur doit déjà être authentifié
    if (!req.user || !req.user.role) {
      return res.status(403).json({ error: "Permissions non disponibles" });
    }

    // Vérifier la permission spécifique
    if (!req.user.role[permissionName]) {
      return res.status(403).json({
        error: `Permission refusée: ${permissionName} requis`,
      });
    }

    next();
  };
}

// ========================================
// ENDPOINT 1 : Health Check
// ========================================
app.get("/health", (req, res) => {
  res.json({ test: "hello world" });
});

// ========================================
// ENDPOINT 2 : Register (Inscription)
// ========================================
app.post("/register", async (req, res) => {
  try {
    const { nom, email, password } = req.body;

    // Validation
    if (!nom || !email || !password) {
      return res.status(400).json({
        error: "Tous les champs sont requis",
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Format email invalide" });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Le mot de passe doit contenir au moins 8 caractères",
      });
    }

    // Vérifier si l'email existe déjà
    const { data: existingUser } = await supabase
      .from("users")
      .select("email")
      .eq("email", email)
      .single();

    if (existingUser) {
      return res.status(409).json({ error: "Email déjà utilisé" });
    }

    // Hasher le mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insérer l'utilisateur (le trigger assignera automatiquement le rôle USER)
    const { data, error } = await supabase
      .from("users")
      .insert([{ nom, email, password: hashedPassword }]).select(`
        id,
        nom,
        email,
        created_at,
        roles (nom)
      `);

    if (error) {
      console.error("Erreur Supabase:", error);
      return res.status(500).json({ error: "Erreur lors de l'inscription" });
    }

    res.status(201).json({
      message: "Inscription réussie",
      user: {
        id: data[0].id,
        nom: data[0].nom,
        email: data[0].email,
        role: data[0].roles?.nom || "USER",
        created_at: data[0].created_at,
      },
    });
  } catch (error) {
    console.error("Erreur serveur:", error);
    res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

// ========================================
// ENDPOINT 3 : Login (Connexion)
// ========================================
app.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({
        error: "Email et mot de passe requis",
      });
    }

    // Récupérer l'utilisateur avec son rôle
    const { data: user, error } = await supabase
      .from("users")
      .select(
        `
        id,
        nom,
        email,
        password,
        roles (
          nom,
          can_post_login,
          can_get_my_user,
          can_get_users,
          can_post_products
        )
      `
      )
      .eq("email", email)
      .single();

    if (error || !user) {
      return res.status(401).json({
        error: "Email ou mot de passe incorrect",
      });
    }

    // Vérifier si l'utilisateur a la permission de se connecter
    if (!user.roles?.can_post_login) {
      return res.status(403).json({
        error: "Votre compte n'a pas la permission de se connecter",
      });
    }

    // Vérifier le mot de passe
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        error: "Email ou mot de passe incorrect",
      });
    }

    // Créer le token JWT (valable 1 heure)
    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.roles.nom,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Connexion réussie",
      token: token,
      expiresIn: 3600, // 1 heure en secondes
      user: {
        id: user.id,
        nom: user.nom,
        email: user.email,
        role: user.roles.nom,
      },
    });
  } catch (error) {
    console.error("Erreur serveur:", error);
    res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

// ========================================
// ENDPOINT 4 : GET /my-user (Mon profil)
// ========================================
app.get(
  "/my-user",
  authenticateToken,
  checkPermission("can_get_my_user"),
  async (req, res) => {
    try {
      // Récupérer les infos complètes de l'utilisateur
      const { data: user, error } = await supabase
        .from("users")
        .select(
          `
          id,
          nom,
          email,
          created_at,
          roles (
            nom,
            can_post_login,
            can_get_my_user,
            can_get_users
          )
        `
        )
        .eq("id", req.user.id)
        .single();

      if (error || !user) {
        return res.status(404).json({ error: "Utilisateur non trouvé" });
      }

      res.json({
        user: {
          id: user.id,
          nom: user.nom,
          email: user.email,
          role: user.roles.nom,
          permissions: {
            can_post_login: user.roles.can_post_login,
            can_get_my_user: user.roles.can_get_my_user,
            can_get_users: user.roles.can_get_users,
            can_post_products: user.roles.can_post_products,
          },
          created_at: user.created_at,
        },
      });
    } catch (error) {
      console.error("Erreur serveur:", error);
      res.status(500).json({ error: "Erreur interne du serveur" });
    }
  }
);

// ========================================
// ENDPOINT 5 : GET /users (Liste des utilisateurs)
// ========================================
app.get(
  "/users",
  authenticateToken,
  checkPermission("can_get_users"),
  async (req, res) => {
    try {
      // Récupérer tous les utilisateurs avec leurs rôles
      const { data: users, error } = await supabase
        .from("users")
        .select(
          `
          id,
          nom,
          email,
          created_at,
          roles (nom)
        `
        )
        .order("created_at", { ascending: false });

      if (error) {
        console.error("Erreur Supabase:", error);
        return res
          .status(500)
          .json({ error: "Erreur lors de la récupération" });
      }

      // Formater la réponse (ne jamais renvoyer les mots de passe)
      const formattedUsers = users.map((user) => ({
        id: user.id,
        nom: user.nom,
        email: user.email,
        role: user.roles?.nom || "N/A",
        created_at: user.created_at,
      }));

      res.json({
        count: formattedUsers.length,
        users: formattedUsers,
      });
    } catch (error) {
      console.error("Erreur serveur:", error);
      res.status(500).json({ error: "Erreur interne du serveur" });
    }
  }
);

// ========================================
// ENDPOINT BONUS : Changer le mot de passe
// ========================================
app.put("/change-password", authenticateToken, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({
        error: "Ancien et nouveau mot de passe requis",
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        error: "Le nouveau mot de passe doit contenir au moins 8 caractères",
      });
    }

    // Récupérer l'utilisateur actuel
    const { data: user } = await supabase
      .from("users")
      .select("password")
      .eq("id", req.user.id)
      .single();

    // Vérifier l'ancien mot de passe
    const isOldPasswordValid = await bcrypt.compare(oldPassword, user.password);

    if (!isOldPasswordValid) {
      return res.status(401).json({ error: "Ancien mot de passe incorrect" });
    }

    // Hasher le nouveau mot de passe
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Mettre à jour le mot de passe ET password_changed_at
    const { error } = await supabase
      .from("users")
      .update({
        password: hashedPassword,
        password_changed_at: new Date().toISOString(),
      })
      .eq("id", req.user.id);

    if (error) {
      console.error("Erreur Supabase:", error);
      return res.status(500).json({ error: "Erreur lors de la mise à jour" });
    }

    res.json({
      message: "Mot de passe changé avec succès. Veuillez vous reconnecter.",
    });
  } catch (error) {
    console.error("Erreur serveur:", error);
    res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

// ========================================
// ENDPOINT 6 : POST /products (Créer un produit)
// ========================================
app.post(
  "/products",
  authenticateToken,
  checkPermission("can_post_products"),
  async (req, res) => {
    try {
      const { title, price } = req.body;

      // Validation
      if (!title || !price) {
        return res.status(400).json({
          error: "Le titre et le prix sont requis",
        });
      }

      // Valider que le prix est un nombre positif
      const priceNum = parseFloat(price);
      if (isNaN(priceNum) || priceNum <= 0) {
        return res.status(400).json({
          error: "Le prix doit être un nombre positif",
        });
      }

      // 1. Créer le produit dans Shopify
      const shopifyProduct = await createShopifyProduct(title, priceNum);

      if (!shopifyProduct.success) {
        return res.status(500).json({
          error: "Échec de la création du produit dans Shopify",
        });
      }

      // 2. Enregistrer le produit dans notre base de données
      const { data: product, error } = await supabase.from("products").insert([
        {
          shopify_id: shopifyProduct.shopify_id,
          created_by: req.user.id,
          product_title: shopifyProduct.title,
          product_price: priceNum,
          sales_count: 0,
        },
      ]).select(`
          id,
          shopify_id,
          product_title,
          product_price,
          sales_count,
          created_at,
          users (
            id,
            nom,
            email
          )
        `);

      if (error) {
        console.error("Erreur Supabase:", error);
        // Si l'enregistrement échoue, on pourrait supprimer le produit de Shopify
        // mais on laisse pour l'instant
        return res.status(500).json({
          error: "Erreur lors de l'enregistrement du produit",
        });
      }

      res.status(201).json({
        message: "Produit créé avec succès",
        product: {
          id: product[0].id,
          shopify_id: product[0].shopify_id,
          title: product[0].product_title,
          price: product[0].product_price,
          sales_count: product[0].sales_count,
          shopify_url: shopifyProduct.shopify_url,
          created_by: {
            id: product[0].users.id,
            nom: product[0].users.nom,
            email: product[0].users.email,
          },
          created_at: product[0].created_at,
        },
      });
    } catch (error) {
      console.error("Erreur serveur:", error);
      res.status(500).json({
        error: error.message || "Erreur interne du serveur",
      });
    }
  }
);

// ========================================
// ENDPOINT 7 : GET /my-products (Mes produits)
// ========================================
app.get("/my-products", authenticateToken, async (req, res) => {
  try {
    // Récupérer tous les produits créés par l'utilisateur connecté
    const { data: products, error } = await supabase
      .from("products")
      .select(
        `
          id,
          shopify_id,
          product_title,
          product_price,
          sales_count,
          created_at,
          updated_at
        `
      )
      .eq("created_by", req.user.id)
      .order("created_at", { ascending: false });

    if (error) {
      console.error("Erreur Supabase:", error);
      return res.status(500).json({
        error: "Erreur lors de la récupération des produits",
      });
    }

    // Calculer des statistiques
    const totalProducts = products.length;
    const totalSales = products.reduce(
      (sum, p) => sum + (p.sales_count || 0),
      0
    );
    const totalRevenue = products.reduce((sum, p) => {
      return sum + (p.product_price || 0) * (p.sales_count || 0);
    }, 0);

    res.json({
      statistics: {
        total_products: totalProducts,
        total_sales: totalSales,
        total_revenue: totalRevenue.toFixed(2),
      },
      products: products.map((p) => ({
        id: p.id,
        shopify_id: p.shopify_id,
        title: p.product_title,
        price: p.product_price,
        sales_count: p.sales_count,
        revenue: (p.product_price * p.sales_count).toFixed(2),
        created_at: p.created_at,
        updated_at: p.updated_at,
        shopify_url: `https://${process.env.SHOPIFY_STORE_URL}/admin/products/${p.shopify_id}`,
      })),
    });
  } catch (error) {
    console.error("Erreur serveur:", error);
    res.status(500).json({
      error: "Erreur interne du serveur",
    });
  }
});

// ========================================
// ENDPOINT 8 : GET /products (Tous les produits)
// ========================================
app.get("/products", authenticateToken, async (req, res) => {
  try {
    // Paramètres de pagination optionnels
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    // Récupérer tous les produits avec infos du créateur
    const {
      data: products,
      error,
      count,
    } = await supabase
      .from("products")
      .select(
        `
          id,
          shopify_id,
          product_title,
          product_price,
          sales_count,
          created_at,
          updated_at,
          users (
            id,
            nom,
            email
          )
        `,
        { count: "exact" }
      )
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) {
      console.error("Erreur Supabase:", error);
      return res.status(500).json({
        error: "Erreur lors de la récupération des produits",
      });
    }

    // Calculer des statistiques globales
    const { data: allProducts } = await supabase
      .from("products")
      .select("product_price, sales_count");

    const totalSales = allProducts.reduce(
      (sum, p) => sum + (p.sales_count || 0),
      0
    );
    const totalRevenue = allProducts.reduce((sum, p) => {
      return sum + (p.product_price || 0) * (p.sales_count || 0);
    }, 0);

    res.json({
      pagination: {
        page,
        limit,
        total: count,
        total_pages: Math.ceil(count / limit),
      },
      statistics: {
        total_products: count,
        total_sales: totalSales,
        total_revenue: totalRevenue.toFixed(2),
      },
      products: products.map((p) => ({
        id: p.id,
        shopify_id: p.shopify_id,
        title: p.product_title,
        price: p.product_price,
        sales_count: p.sales_count,
        revenue: (p.product_price * p.sales_count).toFixed(2),
        created_by: {
          id: p.users.id,
          nom: p.users.nom,
          email: p.users.email,
        },
        created_at: p.created_at,
        updated_at: p.updated_at,
        shopify_url: `https://${process.env.SHOPIFY_STORE_URL}/admin/products/${p.shopify_id}`,
      })),
    });
  } catch (error) {
    console.error("Erreur serveur:", error);
    res.status(500).json({
      error: "Erreur interne du serveur",
    });
  }
});

// ========================================
// DÉMARRAGE DU SERVEUR
// ========================================
app.listen(PORT, () => {
  console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
  console.log(`📊 Health: http://localhost:${PORT}/health`);
  console.log(`🔐 Endpoints protégés:`);
  console.log(`   - POST /login`);
  console.log(`   - GET  /my-user (authentification requise)`);
  console.log(`   - GET  /users (ADMIN uniquement)`);
});
