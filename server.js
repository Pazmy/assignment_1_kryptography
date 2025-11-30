const express = require('express');
const mysql = require('mysql2');
const { encryptXORStream, decryptXORStream, getMasterKeyHex } = require('./utilities');
require('dotenv').config();


const app = express();
app.use(express.json());


const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
}).promise();



app.post('/notes', async (req, res) => {
    try {
      console.log("Headers:", req.headers);
      const { title, content } = req.body;
      if (!title || !content) return res.status(400).json({ error: 'title and content required' });
  
      const keyHex = getMasterKeyHex();
      const { ciphertextHex, nonceHex } = encryptXORStream(content, keyHex);
  
      const [result] = await pool.execute(
        'INSERT INTO notes (title, ciphertext, nonce) VALUES (?, UNHEX(?), ?)',
        [title, ciphertextHex, nonceHex]
      );
      res.status(201).json({ id: result.insertId });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'server error' });
    }
  });
  
  // Read all (decrypt content)
  app.get('/notes', async (req, res) => {
    try {
      const [rows] = await pool.query('SELECT id, title, HEX(ciphertext) AS ciphertextHex, nonce FROM notes ORDER BY created_at DESC');
      const keyHex = getMasterKeyHex();
      const notes = rows.map(r => {
        let plaintext;
        try {
          plaintext = decryptXORStream(r.ciphertextHex, r.nonce, keyHex);
        } catch (e) {
          plaintext = '[decryption error]';
        }
        return { id: r.id, title: r.title, content: plaintext };
      });
      res.json(notes);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'server error' });
    }
  });
  

  app.get('/notes/:id', async (req, res) => {
    try {
      const id = req.params.id;
      const [rows] = await pool.query('SELECT id, title, HEX(ciphertext) AS ciphertextHex, nonce FROM notes WHERE id = ?', [id]);
      if (!rows.length) return res.status(404).json({ error: 'not found' });
      const r = rows[0];
      const keyHex = getMasterKeyHex();
      const content = decryptXORStream(r.ciphertextHex, r.nonce, keyHex);
      res.json({ id: r.id, title: r.title, content });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'server error' });
    }
  });
  

  app.put('/notes/:id', async (req, res) => {
    try {
      const id = req.params.id;
      const { title, content } = req.body;
      if (!title && !content) return res.status(400).json({ error: 'nothing to update' });
  
      const sets = [];
      const params = [];
  
      if (title) {
        sets.push('title = ?');
        params.push(title);
      }
      if (content) {
        const keyHex = getMasterKeyHex();
        const { ciphertextHex, nonceHex } = encryptXORStream(content, keyHex);
        sets.push('ciphertext = UNHEX(?)', 'nonce = ?');
        params.push(ciphertextHex, nonceHex);
      }
  
      params.push(id);
      const sql = `UPDATE notes SET ${sets.join(', ')} WHERE id = ?`;
      const [result] = await pool.execute(sql, params);
      res.json({ affectedRows: result.affectedRows });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'server error' });
    }
  });
  

  app.delete('/notes/:id', async (req, res) => {
    try {
      const id = req.params.id;
      const [result] = await pool.execute('DELETE FROM notes WHERE id = ?', [id]);
      res.json({ affectedRows: result.affectedRows });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'server error' });
    }
  });

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on http://localhost:${port}`));