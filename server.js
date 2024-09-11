const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const FILE_PATH = path.join(__dirname, './notes.json'); // Path to notes.json

app.use(cors());
app.use(bodyParser.json());

// Serve the React frontend build
app.use(express.static(path.join(__dirname, 'public')));

// Function to generate key and IV for encryption
function generateKeyIV(userKey, iv = null) {
  const key = crypto.createHash('sha256').update(userKey).digest().slice(0, 32); // 256-bit key
  return iv ? { key, iv: Buffer.from(iv, 'hex') } : { key, iv: crypto.randomBytes(16) }; // 128-bit IV
}

// Function to encrypt JSON content
function encryptJSON(content, userKey) {
  const { key, iv } = generateKeyIV(userKey);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(JSON.stringify(content), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { iv: iv.toString('hex'), encryptedData: encrypted };
}

// Function to decrypt JSON content
function decryptJSON(encryptedData, userKey) {
  const { key, iv } = generateKeyIV(userKey, encryptedData.iv);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encryptedData.encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

// Endpoint to get notes
app.get('/notes', (req, res) => {
  fs.readFile(FILE_PATH, 'utf8', (err, data) => {
    if (err) {
      console.error('Error reading notes:', err);
      return res.status(500).send('Error reading notes');
    }
    res.json(JSON.parse(data));
  });
});

// Endpoint to encrypt the notes
app.post('/encrypt', (req, res) => {
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

// Endpoint to decrypt the notes
app.post('/decrypt', (req, res) => {
  const { userKey } = req.body;

  if (!userKey) {
    return res.status(400).send('Missing userKey in request');
  }

  let encryptedData;
  try {
    const fileContent = fs.readFileSync(FILE_PATH, 'utf8');
    encryptedData = JSON.parse(fileContent);

    // Check if the file is encrypted
    const isEncrypted = !!encryptedData.encryptedData;

    if (isEncrypted) {
      const decryptedData = decryptJSON(encryptedData, userKey);
      fs.writeFileSync(FILE_PATH, JSON.stringify(decryptedData, null, 2), 'utf8');
      return res.json({ success: true, message: 'Decrypted JSON data has been saved to notes.json', isDecrypted: true });
    } else {
      return res.json({ success: true, message: 'File is already decrypted', isDecrypted: false });
    }
  } catch (error) {
    console.error('Error decrypting JSON data:', error);
    return res.status(500).send('Error decrypting JSON data');
  }
});

// Endpoint to save notes
app.post('/save_notes', (req, res) => {
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

// Serve React app for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
