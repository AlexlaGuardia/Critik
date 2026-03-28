// Intentionally vulnerable file for testing
const express = require('express');
const app = express();

app.use(cors({ origin: '*' }));

const config = {
  NODE_ENV: 'development',
  secure: false,
  httponly: false,
};

const result = eval(userInput);
document.write(unsafeHtml);

app.get('/api/data', (req, res) => {
  res.json({ data: 'public' });
});
