const bcrypt = require("bcrypt");

async function generateHashes() {
  const adminHash = await bcrypt.hash("Admin123!", 10);
  const banHash = await bcrypt.hash("Banned123!", 10);

  console.log("Hash pour admin:", adminHash);
  console.log("Hash pour banned:", banHash);
  console.log("Hash pour utilisateur:", banHash);
}

generateHashes();
