import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import ms from "ms";
import prisma from "../models/index.js";

const register = async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }
  const existing = await prisma.user.findUnique({ where: { username } });
  if (existing) {
    return res.status(409).json({ error: "Username already taken" });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: { username, passwordHash },
  });
  res.status(201).json({ id: user.id, username: user.username });
};

const login = async (req, res) => {
  const { username, password } = req.body;
  const user = await prisma.user.findUnique({ where: { username } });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const jti = uuidv4();
  const accessToken = jwt.sign(
    { sub: user.id, username: user.username, role: user.role, jti },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_TTL }
  );
  const refreshToken = uuidv4();
  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt: new Date(Date.now() + ms(process.env.REFRESH_TOKEN_TTL)),
    },
  });
  res.json({ accessToken, refreshToken });
};

const refresh = async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken)
    return res.status(400).json({ error: "Refresh token required" });
  const tokenRecord = await prisma.refreshToken.findUnique({
    where: { token: refreshToken },
  });
  if (!tokenRecord || tokenRecord.expiresAt < new Date()) {
    if (tokenRecord)
      await prisma.refreshToken.delete({ where: { token: refreshToken } });
    return res.status(401).json({ error: "Invalid or expired refresh token" });
  }
  const user = await prisma.user.findUnique({
    where: { id: tokenRecord.userId },
  });
  if (!user) return res.status(401).json({ error: "User not found" });
  const jti = uuidv4();
  const accessToken = jwt.sign(
    { sub: user.id, username: user.username, role: user.role, jti },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_TTL }
  );
  res.json({ accessToken });
};

const logout = async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken)
    return res.status(400).json({ error: "Refresh token required" });
  await prisma.refreshToken.deleteMany({ where: { token: refreshToken } });
  res.json({ message: "Logged out" });
};

export default {
  register,
  login,
  refresh,
  logout,
};
