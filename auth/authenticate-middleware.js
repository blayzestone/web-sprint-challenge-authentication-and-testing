/* 
  complete the middleware code to check if the user is logged in
  before granting access to the next middleware/route handler
*/
const jwt = require("jsonwebtoken");
const { jwtSecret } = require("../config/constants");

module.exports = (req, res, next) => {
  const token = req.headers.authorization;

  if (token) {
    jwt.verify(token, jwtSecret, (error, decodedToken) => {
      if (error) {
        res.status(401).json({ message: "Invalid token" });
      } else {
        req.local = decodedToken;
        next();
      }
    });
  } else {
    res.status(401).json({ you: "Missing authorization token" });
  }
};
