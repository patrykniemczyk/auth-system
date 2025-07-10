const jwt = require("jsonwebtoken");
const { isTokenRevoked } = require("../services/revokedTokenService");

exports.authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);
  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    if (await isTokenRevoked(payload.jti)) return res.sendStatus(401);
    req.user = payload;
    next();
  } catch (err) {
    return res.sendStatus(401);
  }
};

exports.authorizeRoles =
  (...roles) =>
  (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.sendStatus(403);
    }
    next();
  };
