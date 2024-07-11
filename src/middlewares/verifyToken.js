const jwt = require('jsonwebtoken');
const ENV = require('../config/config');

function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send({ message: 'No token provided.' });

  jwt.verify(token, ENV.jwtSecret, (err, decoded) => {
    if (err) return res.status(500).send({ message: 'Failed to authenticate token.' });
    req.userIdToken = decoded.id;
    next();
  });
}

module.exports = verifyToken;