const crypto = require('crypto');
const fs = require('fs');

// Helper function to generate key from user key
function generateKeyIV(userKey, iv) {
  const key = crypto.createHash('sha256').update(userKey).digest().slice(0, 32); // 256-bit key
  return { key, iv: Buffer.from(iv, 'hex') };
}

// Function to decrypt JSON content
function decryptJSON(encryptedData, userKey) {
  const { key, iv } = generateKeyIV(userKey, encryptedData.iv);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encryptedData.encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

// Path to the notes.json file
const filePath = './notes1.json';

// User key for decryption
const userKey = '1234567';

// Read the encrypted data from the file
const fileContent = fs.readFileSync(filePath, 'utf8');
const encryptedData = JSON.parse(fileContent);

// Decrypt the JSON data
try {
  const decryptedData = decryptJSON(encryptedData, userKey);
  console.log('Decrypted JSON Data:', JSON.stringify(decryptedData, null, 2));
  fs.writeFileSync(filePath, JSON.stringify(decryptedData, null, 2), 'utf8');
  console.log('Decrypted JSON data has been saved to notes.json');
} catch (error) {
  console.error('Error decrypting JSON data:', error);
}
