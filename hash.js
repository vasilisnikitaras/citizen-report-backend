import bcrypt from "bcryptjs";

async function makeHash(pwd) {
  const hash = await bcrypt.hash(pwd, 10);
  console.log(pwd, "→", hash);
}

makeHash("admin123");
makeHash("fanes123");
makeHash("rhodes123");
makeHash("police123");
makeHash("office123");
