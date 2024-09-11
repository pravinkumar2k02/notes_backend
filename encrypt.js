const crypto = require('crypto');
const fs = require('fs');

// Helper function to generate key and IV from user key
function generateKeyIV(userKey) {
  const key = crypto.createHash('sha256').update(userKey).digest().slice(0, 32); // 256-bit key
  const iv = crypto.randomBytes(16); // 128-bit IV
  return { key, iv };
}

// Function to encrypt JSON content
function encryptJSON(content, userKey) {
  const { key, iv } = generateKeyIV(userKey);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(JSON.stringify(content), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { iv: iv.toString('hex'), encryptedData: encrypted };
}

// Path to the notes.json file
const filePath = './notes.json';

// User key for encryption
const userKey = '1234567';

// Read the existing JSON data from the file
let jsonData;

try {
  const fileContent = fs.readFileSync(filePath, 'utf8');
  jsonData = JSON.parse(fileContent);
} catch (err) {
  console.error('Error reading or parsing the file:', err);
  process.exit(1);
}

// Encrypt the JSON data
const encryptedData = encryptJSON(jsonData, userKey);

// Save the encrypted data to the file
fs.writeFileSync(filePath, JSON.stringify(encryptedData, null, 2), 'utf8');

console.log('Encrypted JSON data has been saved to notes.json');
