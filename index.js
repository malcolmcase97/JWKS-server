const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

app.get('/', (req, res) => {
  res.send('JWKS Server is running!');
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
