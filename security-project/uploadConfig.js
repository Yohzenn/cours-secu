// ========================================
// CONFIGURATION DE L'UPLOAD D'IMAGES
// ========================================
const multer = require("multer");
const path = require("path");
const crypto = require("crypto");

// Configuration du stockage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, process.env.UPLOAD_DIR || "./uploads");
  },
  filename: function (req, file, cb) {
    // Générer un nom unique pour éviter les collisions
    const uniqueSuffix = crypto.randomBytes(16).toString("hex");
    const ext = path.extname(file.originalname);
    cb(null, `product-${uniqueSuffix}${ext}`);
  },
});

// Filtrer les types de fichiers acceptés
const fileFilter = (req, file, cb) => {
  // Extensions autorisées
  const allowedExtensions = [".jpg", ".jpeg", ".png", ".gif", ".webp"];
  const ext = path.extname(file.originalname).toLowerCase();

  // Types MIME autorisés
  const allowedMimeTypes = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
  ];

  if (
    allowedExtensions.includes(ext) &&
    allowedMimeTypes.includes(file.mimetype)
  ) {
    cb(null, true);
  } else {
    cb(
      new Error("Type de fichier non autorisé. Utilisez JPG, PNG, GIF ou WebP.")
    );
  }
};

// Configuration de Multer
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024, // 5MB par défaut
  },
});

module.exports = upload;
