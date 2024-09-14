// require('dotenv').config(); // Use dotenv for environment variables
const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 5000;
const FILE_PATH = path.join(__dirname, './notes.json'); // Path to notes.json

// Use environment variable for auth token
const AUTH_TOKEN = process.env.PRIVATE_AUTH_TOKEN; 
// const AUTH_TOKEN = 'ffdr4eFD5rcgfhREE344e4e';

// Middleware for security
app.use(helmet()); // Set various HTTP headers for security
app.use(cors({ origin: 'https://crypto-private-notes.netlify.app', credentials: true })); // Restrict origins
// app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '../my_app/build'))); // Serve React frontend

// Log all requests
app.use(morgan('combined')); // For logging HTTP requests and errors

// Rate limiting to prevent brute-force attacks
const limiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 2000, // Limit each IP to 2000 requests per window
  message: 'Too many requests from this IP, please try again after 5 minutes'
});
app.use(limiter);

// Authentication Middleware
function authenticate(req, res, next) {
  const token = req.headers['authorization'];
  if (token && token === `Bearer ${AUTH_TOKEN}`) {
    next();
  } else {
    return res.status(401).send('Unauthorized');
  }
}

// Generate encryption key and IV
function generateKeyIV(userKey, iv = null) {
  const key = crypto.createHash('sha256').update(userKey).digest().slice(0, 32); // 256-bit key
  return iv ? { key, iv: Buffer.from(iv, 'hex') } : { key, iv: crypto.randomBytes(16) }; // 128-bit IV
}

// Encrypt JSON data
function encryptJSON(content, userKey) {
  const { key, iv } = generateKeyIV(userKey);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(JSON.stringify(content), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { iv: iv.toString('hex'), encryptedData: encrypted };
}

// Decrypt JSON data
function decryptJSON(encryptedData, userKey) {
  const { key, iv } = generateKeyIV(userKey, encryptedData.iv);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encryptedData.encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

//keep alive
app.get('/keep-alive', authenticate, (req, res) => {
  res.status(200).json({ message: 'Server is alive' });
  console.log("server is alive");
});

// Endpoint to get notes (read-only)
app.get('/notes', authenticate, (req, res) => {
  try {
    const data = fs.readFileSync(FILE_PATH, 'utf8');
    return res.json(JSON.parse(data));
  } catch (err) {
    console.error('Error reading notes:', err);
    return res.status(500).send('Error reading notes');
  }
});

// Validate and sanitize input before encrypting
app.post('/encrypt', authenticate, [
  body('userKey').isLength({ min: 8 }).matches(/[A-Z]/).withMessage('Weak key: must be at least 8 characters and contain an uppercase letter'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { userKey } = req.body;
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

// Validate and sanitize input before decrypting
app.post('/decrypt', authenticate, [
  body('userKey').isLength({ min: 8 }).matches(/[A-Z]/).withMessage('Weak key: must be at least 8 characters and contain an uppercase letter'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { userKey } = req.body;
  let encryptedData;
  try {
    const fileContent = fs.readFileSync(FILE_PATH, 'utf8');
    encryptedData = JSON.parse(fileContent);

    // Check if the file is encrypted by looking for encryptedData.encryptedData
    const isDecrypted = !!encryptedData.encryptedData;

    if (isDecrypted) {
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

// Validate input and save notes
app.post('/save_notes', authenticate, [
  body('notes').isObject().withMessage('Invalid notes format'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const newNotes = req.body.notes;
  fs.writeFile(FILE_PATH, JSON.stringify(newNotes, null, 2), 'utf8', (err) => {
    if (err) {
      console.error('Error writing to notes file:', err);
      return res.status(500).send('Error saving notes');
    }
    res.send('Notes saved successfully');
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
