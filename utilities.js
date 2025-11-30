const crypto = require('crypto');

// keystream generator: H = SHA256(key || nonce || counter), stream of bytes
function keystreamBytes(keyBuf, nonceBuf, length) {
    const chunks = [];
    let counter = 0;
    let produced = 0;
    while (produced < length) {
      const ctrBuf = Buffer.allocUnsafe(4);
      ctrBuf.writeUInt32BE(counter);
      const hash = crypto.createHash('sha256');
      hash.update(keyBuf);
      hash.update(nonceBuf);
      hash.update(ctrBuf);
      const block = hash.digest(); // 32 bytes
      const need = Math.min(block.length, length - produced);
      chunks.push(block.slice(0, need));
      produced += need;
      counter += 1;
    }
    return Buffer.concat(chunks, length);
  }
  
  function xorBuffers(bufA, bufB) {
    const out = Buffer.allocUnsafe(bufA.length);
    for (let i = 0; i < bufA.length; i++) out[i] = bufA[i] ^ bufB[i];
    return out;
  }
  
  function encryptXORStream(plaintext, keyHex) {
    // plaintext: string or Buffer
    const keyBuf = Buffer.from(keyHex, 'hex');
    const nonce = crypto.randomBytes(12); // 12-byte nonce
    const ptBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
    const ks = keystreamBytes(keyBuf, nonce, ptBuf.length);
    const ct = xorBuffers(ptBuf, ks);
    return {
      ciphertextHex: ct.toString('hex'),
      nonceHex: nonce.toString('hex'),
    };
  }
  
  function decryptXORStream(ciphertextHex, nonceHex, keyHex) {
    const ctBuf = Buffer.from(ciphertextHex, 'hex');
    const keyBuf = Buffer.from(keyHex, 'hex');
    const nonceBuf = Buffer.from(nonceHex, 'hex');
    const ks = keystreamBytes(keyBuf, nonceBuf, ctBuf.length);
    const pt = xorBuffers(ctBuf, ks);
    return pt.toString('utf8'); // format utf8 plaintext
  }
  
  // Helper to get master key as hex
  function getMasterKeyHex() {
    // derive fixed-length key from master passphrase using SHA-256
    const pass = process.env.MASTER_KEY || 'default_master_key_change_me';
    return crypto.createHash('sha256').update(pass).digest('hex'); // 32 bytes hex
  }
  
  module.exports = {
    encryptXORStream,
    decryptXORStream,
    getMasterKeyHex,
  };