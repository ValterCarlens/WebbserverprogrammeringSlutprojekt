const CryptoJS = require('crypto-js');

const DEFAULT_SECRET = 'supersecretkey'; // Change this for production

function encrypt(text, secret = DEFAULT_SECRET) {
  return CryptoJS.AES.encrypt(text, secret).toString();
}

function decrypt(ciphertext, secret = DEFAULT_SECRET) {
  const bytes = CryptoJS.AES.decrypt(ciphertext, secret);
  return bytes.toString(CryptoJS.enc.Utf8);
}

module.exports = { encrypt, decrypt }; 