import dotenv from "dotenv";
dotenv.config();

console.log("DB:", process.env.DATABASE_URL);

import bcrypt from "bcryptjs";
import pkg from 'pg';
const { Client } = pkg;

const client = new Client({
  connectionString: process.env.DATABASE_URL,
});

// Rhodes (44 villages) + Canada (13 major cities)
const communities = [
  // Rhodes
  "Afantou","Apolakkia","Archangelos","Asklipio","Damatria","Empona","Fanes","Gennadi",
  "Ialysos","Istrios","Kalathos","Kallithea","Kattavia","Kefalos","Kremasti","Koskinou",
  "Kritinia","Lachania","Lardos","Lindos","Malona","Maritsa","Masari","Monolithos",
  "Paradisi","Pastida","Pefki","Pilona","Platania","Profilia","Salakos","Siana",
  "Soroni","Theologos","Trianta","Vati","Vlycha","Vourlida","Kalythies",
  "Agios Isidoros","Agios Georgios","Agios Nikolaos","Agios Pavlos",

  // Canada
  "Laval","Montreal","Quebec City","Toronto","Ottawa","Mississauga","Brampton",
  "Hamilton","Vancouver","Calgary","Edmonton","Winnipeg","Halifax"
];

async function createUsers() {
  await client.connect();

  for (let c of communities) {
    for (let i = 1; i <= 100; i++) {
      const username = `${c.toLowerCase().replace(/ /g, "_")}_user${i}`;
      const password = `${c.toLowerCase().replace(/ /g, "")}${i}`;
      const role = "user";
      const community = c;

      const email = `${username}@example.com`;

      const hash = await bcrypt.hash(password, 10);

      await client.query(
        `INSERT INTO users (username, email, password, role, community)
         VALUES ($1, $2, $3, $4, $5)`,
        [username, email, hash, role, community]
      );

      console.log(`Created: ${username} (${community})`);
    }
  }

  await client.end();
}

createUsers();
