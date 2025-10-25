// ========================================
// IMPORTS ET CONFIGURATION
// ========================================
require("dotenv").config();
const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { createShopifyProduct } = require("./shopify");
const { authenticate, checkPermission } = require("./authMiddleware");
const { generateApiKey, hashApiKey, maskApiKey } = require("./apiKeys");
const {
  verifyShopifyWebhook,
  parseOrderProducts,
  validateWebhookPayload,
  extractWebhookMetadata,
} = require("./webhooks");
const upload = require("./uploadConfig");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware pour parser le JSON
app.use(express.json());

// Servir les fichiers statiques (images uploadées)
app.use("/uploads", express.static("uploads"));

// Initialiser Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// ========================================
// RATE LIMITING
// ========================================
const loginLimiter = rateLimit({
  windowMs: 5 * 1000,
  max: 1,
  message: {
    error: "Trop de tentatives de connexion. Réessayez dans 5 secondes.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// ========================================
// ENDPOINT 1 : Health Check
// ========================================
app.get("/health", (req, res) => {
  res.json({
    test: "hello world",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// ========================================
// ENDPOINT 2 : Register
// ========================================
app.post("/register", async (req, res) => {
  try {
    const { nom, email, password } = req.body;

    if (!nom || !email || !password) {
      return res.status(400).json({ error: "Tous les champs sont requis" });
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

    const { data: existingUser } = await supabase
      .from("users")
      .select("email")
      .eq("email", email)
      .single();

    if (existingUser) {
      return res.status(409).json({ error: "Email déjà utilisé" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

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
// ENDPOINT 3 : Login
// ========================================
app.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email et mot de passe requis" });
    }

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
          can_post_products,
          can_upload_product_image,
          can_get_bestsellers
        )
      `
      )
      .eq("email", email)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: "Email ou mot de passe incorrect" });
    }

    if (!user.roles?.can_post_login) {
      return res.status(403).json({
        error: "Votre compte n'a pas la permission de se connecter",
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Email ou mot de passe incorrect" });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.roles.nom },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Connexion réussie",
      token: token,
      expiresIn: 3600,
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
// ENDPOINT 4 : GET /my-user
// ========================================
app.get(
  "/my-user",
  authenticate,
  checkPermission("can_get_my_user"),
  async (req, res) => {
    try {
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
          can_get_users,
          can_post_products,
          can_upload_product_image,
          can_get_bestsellers
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
          permissions: user.roles,
          created_at: user.created_at,
          auth_method: req.user.authMethod,
        },
      });
    } catch (error) {
      console.error("Erreur serveur:", error);
      res.status(500).json({ error: "Erreur interne du serveur" });
    }
  }
);

// ========================================
// ENDPOINT 5 : GET /users
// ========================================
app.get(
  "/users",
  authenticate,
  checkPermission("can_get_users"),
  async (req, res) => {
    try {
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
// ENDPOINT 6 : PUT /change-password
// ========================================
app.put("/change-password", authenticate, async (req, res) => {
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

    if (!user) {
      return res.status(404).json({ error: "Utilisateur non trouvé" });
    }

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
      message:
        "Mot de passe changé avec succès. Tous vos tokens JWT sont maintenant invalides. Veuillez vous reconnecter.",
      warning: "Les API Keys restent valides.",
    });
  } catch (error) {
    console.error("Erreur serveur:", error);
    res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

// ========================================
// PARTIE 5 : API KEYS
// ========================================

// ENDPOINT 6 : POST /api-keys - Créer une clé API
app.post("/api-keys", authenticate, async (req, res) => {
  try {
    const { name } = req.body;

    if (!name || name.trim().length === 0) {
      return res.status(400).json({
        error: "Le nom de la clé API est requis",
      });
    }

    // Vérifier si le nom existe déjà pour cet utilisateur
    const { data: existing } = await supabase
      .from("api_keys")
      .select("name")
      .eq("user_id", req.user.id)
      .eq("name", name.trim())
      .single();

    if (existing) {
      return res.status(409).json({
        error: "Une clé avec ce nom existe déjà",
      });
    }

    // Générer la clé API
    const { key, prefix } = generateApiKey("live");
    const keyHash = await hashApiKey(key);

    // Enregistrer en base de données
    const { data, error } = await supabase
      .from("api_keys")
      .insert([
        {
          key_hash: keyHash,
          key_prefix: prefix,
          name: name.trim(),
          user_id: req.user.id,
          is_active: true,
        },
      ])
      .select("id, name, key_prefix, created_at");

    if (error) {
      console.error("Erreur Supabase:", error);
      return res.status(500).json({ error: "Erreur lors de la création" });
    }

    res.status(201).json({
      message: "Clé API créée avec succès",
      warning:
        "⚠️ Copiez cette clé maintenant, elle ne sera plus jamais affichée !",
      api_key: key,
      key_info: {
        id: data[0].id,
        name: data[0].name,
        prefix: data[0].key_prefix,
        created_at: data[0].created_at,
      },
    });
  } catch (error) {
    console.error("Erreur serveur:", error);
    res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

// ENDPOINT 7 : GET /api-keys - Liste des clés API
app.get("/api-keys", authenticate, async (req, res) => {
  try {
    const { data: apiKeys, error } = await supabase
      .from("api_keys")
      .select(
        "id, name, key_prefix, is_active, last_used_at, usage_count, created_at"
      )
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false });

    if (error) {
      console.error("Erreur Supabase:", error);
      return res.status(500).json({ error: "Erreur lors de la récupération" });
    }

    res.json({
      count: apiKeys.length,
      api_keys: apiKeys.map((key) => ({
        id: key.id,
        name: key.name,
        prefix: key.key_prefix,
        is_active: key.is_active,
        last_used_at: key.last_used_at,
        usage_count: key.usage_count,
        created_at: key.created_at,
      })),
    });
  } catch (error) {
    console.error("Erreur serveur:", error);
    res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

// ENDPOINT 8 : DELETE /api-keys/:id - Supprimer une clé API
app.delete("/api-keys/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    // Vérifier que la clé appartient à l'utilisateur
    const { data: apiKey } = await supabase
      .from("api_keys")
      .select("user_id, name")
      .eq("id", id)
      .single();

    if (!apiKey) {
      return res.status(404).json({ error: "Clé API non trouvée" });
    }

    if (apiKey.user_id !== req.user.id) {
      return res.status(403).json({
        error: "Vous ne pouvez supprimer que vos propres clés",
      });
    }

    // Supprimer la clé
    const { error } = await supabase.from("api_keys").delete().eq("id", id);

    if (error) {
      console.error("Erreur Supabase:", error);
      return res.status(500).json({ error: "Erreur lors de la suppression" });
    }

    res.json({
      message: "Clé API supprimée avec succès",
      deleted_key: apiKey.name,
    });
  } catch (error) {
    console.error("Erreur serveur:", error);
    res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

// ========================================
// PRODUITS (avec support images pour PREMIUM)
// ========================================

// ENDPOINT 9 : POST /products - Créer un produit
app.post(
  "/products",
  authenticate,
  checkPermission("can_post_products"),
  upload.single("image"),
  async (req, res) => {
    try {
      const { title, price } = req.body;

      if (!title || !price) {
        return res
          .status(400)
          .json({ error: "Le titre et le prix sont requis" });
      }

      const priceNum = parseFloat(price);
      if (isNaN(priceNum) || priceNum <= 0) {
        return res
          .status(400)
          .json({ error: "Le prix doit être un nombre positif" });
      }

      // Vérifier si l'utilisateur a uploadé une image
      let imageUrl = null;
      let imageShopifyId = null;

      if (req.file) {
        // Vérifier la permission d'upload d'image
        if (!req.user.role.can_upload_product_image) {
          // Supprimer le fichier uploadé
          fs.unlinkSync(req.file.path);
          return res.status(403).json({
            error:
              "Permission refusée: Upgrade vers PREMIUM pour uploader des images",
          });
        }

        // Construire l'URL de l'image
        imageUrl = `${req.protocol}://${req.get("host")}/uploads/${
          req.file.filename
        }`;
      }

      // Créer le produit dans Shopify
      const shopifyProduct = await createShopifyProduct(title, priceNum);

      if (!shopifyProduct.success) {
        // Supprimer l'image si la création Shopify échoue
        if (req.file) {
          fs.unlinkSync(req.file.path);
        }
        return res.status(500).json({
          error: "Échec de la création du produit dans Shopify",
        });
      }

      // Enregistrer dans la base de données
      const { data: product, error } = await supabase.from("products").insert([
        {
          shopify_id: shopifyProduct.shopify_id,
          created_by: req.user.id,
          product_title: shopifyProduct.title,
          product_price: priceNum,
          sales_count: 0,
          image_url: imageUrl,
        },
      ]).select(`
        id,
        shopify_id,
        product_title,
        product_price,
        sales_count,
        image_url,
        created_at,
        users (id, nom, email)
      `);

      if (error) {
        console.error("Erreur Supabase:", error);
        if (req.file) {
          fs.unlinkSync(req.file.path);
        }
        return res
          .status(500)
          .json({ error: "Erreur lors de l'enregistrement" });
      }

      res.status(201).json({
        message: "Produit créé avec succès",
        product: {
          id: product[0].id,
          shopify_id: product[0].shopify_id,
          title: product[0].product_title,
          price: product[0].product_price,
          sales_count: product[0].sales_count,
          image_url: product[0].image_url,
          shopify_url: shopifyProduct.shopify_url,
          created_by: product[0].users,
          created_at: product[0].created_at,
        },
      });
    } catch (error) {
      console.error("Erreur serveur:", error);
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }
      res
        .status(500)
        .json({ error: error.message || "Erreur interne du serveur" });
    }
  }
);

// ENDPOINT 10 : GET /my-products
app.get("/my-products", authenticate, async (req, res) => {
  try {
    const { data: products, error } = await supabase
      .from("products")
      .select("*")
      .eq("created_by", req.user.id)
      .order("created_at", { ascending: false });

    if (error) {
      console.error("Erreur Supabase:", error);
      return res.status(500).json({ error: "Erreur lors de la récupération" });
    }

    const totalSales = products.reduce(
      (sum, p) => sum + (p.sales_count || 0),
      0
    );
    const totalRevenue = products.reduce((sum, p) => {
      return sum + (p.product_price || 0) * (p.sales_count || 0);
    }, 0);

    res.json({
      statistics: {
        total_products: products.length,
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
        image_url: p.image_url,
        created_at: p.created_at,
        shopify_url: `https://${process.env.SHOPIFY_STORE_URL}/admin/products/${p.shopify_id}`,
      })),
    });
  } catch (error) {
    console.error("Erreur serveur:", error);
    res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

// ENDPOINT 11 : GET /products
app.get("/products", authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    const {
      data: products,
      error,
      count,
    } = await supabase
      .from("products")
      .select(
        `
        *,
        users (id, nom, email)
      `,
        { count: "exact" }
      )
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) {
      console.error("Erreur Supabase:", error);
      return res.status(500).json({ error: "Erreur lors de la récupération" });
    }

    res.json({
      pagination: {
        page,
        limit,
        total: count,
        total_pages: Math.ceil(count / limit),
      },
      products: products.map((p) => ({
        id: p.id,
        shopify_id: p.shopify_id,
        title: p.product_title,
        price: p.product_price,
        sales_count: p.sales_count,
        image_url: p.image_url,
        created_by: p.users,
        created_at: p.created_at,
      })),
    });
  } catch (error) {
    console.error("Erreur serveur:", error);
    res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

// ========================================
// PARTIE 6 : WEBHOOKS SHOPIFY
// ========================================

// ENDPOINT 12 : POST /webhooks/shopify-sales
app.post(
  "/webhooks/shopify-sales",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      // Récupérer les headers Shopify
      const hmacHeader = req.headers["x-shopify-hmac-sha256"];
      const topic = req.headers["x-shopify-topic"];
      const shopifyDomain = req.headers["x-shopify-shop-domain"];

      // Vérifier la signature HMAC
      const rawBody = req.body.toString("utf8");
      const isValid = verifyShopifyWebhook(
        rawBody,
        hmacHeader,
        process.env.SHOPIFY_WEBHOOK_SECRET
      );

      if (!isValid) {
        console.error("Signature HMAC invalide");
        return res.status(401).json({ error: "Signature invalide" });
      }

      // Parser le payload
      const payload = JSON.parse(rawBody);

      // Valider le payload
      const validation = validateWebhookPayload(payload, "orders/create");
      if (!validation.valid) {
        console.error("Payload invalide:", validation.error);
        return res.status(400).json({ error: validation.error });
      }

      // Logger le webhook
      const metadata = extractWebhookMetadata(payload);
      await supabase.from("webhook_logs").insert([
        {
          event_type: topic || "orders/create",
          shopify_event_id: payload.id?.toString(),
          payload: payload,
          status: "processing",
          signature_valid: true,
        },
      ]);

      // Extraire les produits de la commande
      const orderProducts = parseOrderProducts(payload);

      if (orderProducts.length === 0) {
        console.log("Aucun produit dans la commande");
        return res.status(200).json({ message: "Aucun produit à traiter" });
      }

      // Mettre à jour le sales_count pour chaque produit
      for (const item of orderProducts) {
        const { data: product } = await supabase
          .from("products")
          .select("id, sales_count")
          .eq("shopify_id", item.shopify_id)
          .single();

        if (product) {
          await supabase
            .from("products")
            .update({
              sales_count: product.sales_count + item.quantity,
            })
            .eq("id", product.id);

          console.log(
            `✅ Produit ${item.shopify_id}: +${item.quantity} ventes`
          );
        }
      }

      // Marquer le webhook comme traité
      await supabase
        .from("webhook_logs")
        .update({
          status: "processed",
          processed_at: new Date().toISOString(),
        })
        .eq("shopify_event_id", payload.id?.toString());

      res.status(200).json({
        message: "Webhook traité avec succès",
        products_updated: orderProducts.length,
      });
    } catch (error) {
      console.error("Erreur webhook:", error);

      // Logger l'erreur
      try {
        await supabase
          .from("webhook_logs")
          .update({
            status: "failed",
            error_message: error.message,
          })
          .eq("shopify_event_id", req.body?.id?.toString());
      } catch (logError) {
        console.error("Erreur logging:", logError);
      }

      res.status(500).json({ error: "Erreur lors du traitement" });
    }
  }
);

// ========================================
// PARTIE 7 : PREMIUM - BESTSELLERS
// ========================================

// ENDPOINT 13 : GET /my-bestsellers (PREMIUM)
app.get(
  "/my-bestsellers",
  authenticate,
  checkPermission("can_get_bestsellers"),
  async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 10;

      const { data: products, error } = await supabase
        .from("products")
        .select("*")
        .eq("created_by", req.user.id)
        .order("sales_count", { ascending: false })
        .limit(limit);

      if (error) {
        console.error("Erreur Supabase:", error);
        return res
          .status(500)
          .json({ error: "Erreur lors de la récupération" });
      }

      res.json({
        message: "🏆 Vos meilleurs produits",
        user_role: req.user.role.nom,
        total_bestsellers: products.length,
        bestsellers: products.map((p, index) => ({
          rank: index + 1,
          id: p.id,
          shopify_id: p.shopify_id,
          title: p.product_title,
          price: p.product_price,
          sales_count: p.sales_count,
          revenue: (p.product_price * p.sales_count).toFixed(2),
          image_url: p.image_url,
          created_at: p.created_at,
        })),
      });
    } catch (error) {
      console.error("Erreur serveur:", error);
      res.status(500).json({ error: "Erreur interne du serveur" });
    }
  }
);

// ========================================
// DÉMARRAGE DU SERVEUR
// ========================================
app.listen(PORT, () => {
  console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
  console.log(`\n📊 Endpoints disponibles:`);
  console.log(`   - GET  /health`);
  console.log(`   - POST /register`);
  console.log(`   - POST /login`);
  console.log(`\n🔐 Authentification (JWT ou API Key):`);
  console.log(`   - GET  /my-user`);
  console.log(`   - GET  /users (ADMIN)`);
  console.log(`   - PUT  /change-password`);
  console.log(`\n🔑 API Keys:`);
  console.log(`   - POST   /api-keys (créer)`);
  console.log(`   - GET    /api-keys (lister)`);
  console.log(`   - DELETE /api-keys/:id (supprimer)`);
  console.log(`\n🛍️  Produits:`);
  console.log(`   - POST /products (avec image si PREMIUM)`);
  console.log(`   - GET  /my-products`);
  console.log(`   - GET  /products`);
  console.log(`\n🪝  Webhooks:`);
  console.log(`   - POST /webhooks/shopify-sales`);
  console.log(`\n⭐ Premium:`);
  console.log(`   - GET  /my-bestsellers (PREMIUM)`);
});
