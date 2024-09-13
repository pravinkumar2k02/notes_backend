const express = require('express');
const fs = require('fs');
const CryptoJS = require('crypto-js');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;
const FILE_PATH = path.join(__dirname, './notes.json'); // Path to notes.json

const AUTH_TOKEN = '################'; // Replace with your actual auth token
// const AUTH_TOKEN = process.env.PRIVATE_AUTH_TOKEN;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '../my_app/build'))); // Serve React frontend

// Authentication Middleware
function authenticate(req, res, next) {
  const token = req.headers['authorization'];
  if (token && token === `Bearer ${AUTH_TOKEN}`) {
    next();
  } else {
    res.status(401).send('Unauthorized');
  }
}

function generateKeyIV(userKey, iv = null) {
  const key = crypto.createHash('sha256').update(userKey).digest().slice(0, 32); // 256-bit key
  return iv ? { key, iv: Buffer.from(iv, 'hex') } : { key, iv: crypto.randomBytes(16) }; // 128-bit IV
}

function encryptJSON(content, userKey) {
  const { key, iv } = generateKeyIV(userKey);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(JSON.stringify(content), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { iv: iv.toString('hex'), encryptedData: encrypted };
}

function decryptJSON(encryptedData, userKey) {
  const { key, iv } = generateKeyIV(userKey, encryptedData.iv);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encryptedData.encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

// Endpoint to get notes
app.get('/notes', authenticate, (req, res) => {
  fs.readFile(FILE_PATH, 'utf8', (err, data) => {
    if (err) {
      console.error('Error reading notes:', err);
      return res.status(500).send('Error reading notes');
    }
    res.json(JSON.parse(data));
  });
});

app.post('/encrypt', authenticate, (req, res) => {
  const { userKey } = req.body;

  if (!userKey) {
    return res.status(400).send('Missing userKey in request');
  }

  let jsonData;
  try {
    const fileContent = fs.readFileSync(FILE_PATH, 'utf8');
    jsonData = JSON.parse(fileContent);
  } catch (err) {
    console.error('Error reading or parsing the file:', err);
    return res.status(500).send('Error reading or parsing the file');
  }

  const encryptedData = encryptJSON(jsonData, userKey);

  fs.writeFileSync(FILE_PATH, JSON.stringify(encryptedData, null, 2), 'utf8');
  res.send('Encrypted JSON data has been saved to notes.json');
});

app.post('/decrypt', authenticate, (req, res) => {
  const { userKey } = req.body;
 console.log("decrypting");
  if (!userKey) {
    return res.status(400).send('Missing userKey in request');
  }

  let encryptedData;
  try {
    const fileContent = fs.readFileSync(FILE_PATH, 'utf8');
    encryptedData = JSON.parse(fileContent);

    // Check if the file is encrypted by looking for encryptedData.encryptedData
    const isDecrypted = !!encryptedData.encryptedData;

    if (isDecrypted) {
      // Try to decrypt
      const decryptedData = decryptJSON(encryptedData, userKey);
      fs.writeFileSync(FILE_PATH, JSON.stringify(decryptedData, null, 2), 'utf8');
      return res.json({ success: true, message: 'Decrypted JSON data has been saved to notes.json', isDecrypted: true });
    } else {
      // File is already decrypted
      return res.json({ success: true, message: 'File is already decrypted', isDecrypted: false });
    }
  } catch (error) {
    console.error('Error decrypting JSON data:', error);
    return res.status(500).send('Error decrypting JSON data');
  }
});

app.post('/save_notes', authenticate, (req, res) => {
  const newNotes = req.body.notes;

  // Write updated notes to the file
  fs.writeFile(FILE_PATH, JSON.stringify(newNotes, null, 2), 'utf8', (err) => {
    if (err) {
      console.error('Error writing to notes file:', err);
      return res.status(500).send('Error saving notes');
    }
    res.send('Notes saved successfully');
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
