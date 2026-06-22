const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const { verifyToken } = require('../middleware/auth');
require('dotenv').config({ path: require('path').join(__dirname, '../../.env') });

const router = express.Router();

// GET /api/user/organizations — public, for dropdowns
router.get('/organizations', (req, res) => {
  const orgs = db.prepare('SELECT id, name FROM organizations ORDER BY name ASC').all();
  return res.json(orgs);
});

// POST /api/user/signup
router.post('/signup', (req, res) => {
  const { email, password, org_id } = req.body;
  if (!email || !password || !org_id) {
    return res.status(400).json({ error: 'Email, password, and org_id required' });
  }
  const org = db.prepare('SELECT id FROM organizations WHERE id = ?').get(org_id);
  if (!org) return res.status(404).json({ error: 'Organization not found' });

  const hash = bcrypt.hashSync(password, 10);
  try {
    const result = db.prepare(
      'INSERT INTO users (email, password_hash, role, org_id) VALUES (?, ?, ?, ?)'
    ).run(email.trim().toLowerCase(), hash, 'end_user', org_id);
    const user = db.prepare('SELECT id, email, role, org_id, created_at FROM users WHERE id = ?').get(result.lastInsertRowid);
    return res.status(201).json(user);
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    throw err;
  }
});

// POST /api/user/login
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND role = ?')
    .get(email.trim().toLowerCase(), 'end_user');
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const org = db.prepare('SELECT name FROM organizations WHERE id = ?').get(user.org_id);
  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role, org_id: user.org_id },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN }
  );
  return res.json({ token, org_id: user.org_id, org_name: org.name });
});

// POST /api/user/check-flag — works with or without auth
// With auth: org_id comes from token; without auth: org_id must be in body
router.post('/check-flag', (req, res) => {
  const authHeader = req.headers['authorization'];
  let org_id = req.body.org_id;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const decoded = jwt.verify(authHeader.split(' ')[1], process.env.JWT_SECRET);
      org_id = decoded.org_id;
    } catch { /* use body org_id if token invalid */ }
  }

  const { feature_key } = req.body;
  if (!org_id || !feature_key || !feature_key.trim()) {
    return res.status(400).json({ error: 'org_id and feature_key required' });
  }

  const org = db.prepare('SELECT id, name FROM organizations WHERE id = ?').get(org_id);
  if (!org) return res.status(404).json({ error: 'Organization not found' });

  const key = feature_key.trim().toLowerCase().replace(/\s+/g, '_');
  const flag = db.prepare('SELECT key, enabled FROM feature_flags WHERE key = ? AND org_id = ?').get(key, org_id);

  if (!flag) {
    return res.status(404).json({ error: `Feature "${key}" not found for organization "${org.name}"` });
  }

  return res.json({ org: org.name, feature_key: flag.key, enabled: flag.enabled === 1 });
});

module.exports = router;
