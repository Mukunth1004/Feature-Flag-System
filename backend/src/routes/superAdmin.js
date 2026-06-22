const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('../db');
const { requireSuperAdmin } = require('../middleware/auth');
require('dotenv').config({ path: require('path').join(__dirname, '../../.env') });

const router = express.Router();

// POST /api/super-admin/login
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  if (
    email !== process.env.SUPER_ADMIN_EMAIL ||
    password !== process.env.SUPER_ADMIN_PASSWORD
  ) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign(
    { role: 'super_admin', email },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN }
  );
  return res.json({ token });
});

// POST /api/super-admin/organizations
router.post('/organizations', requireSuperAdmin, (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'Organization name required' });
  }
  try {
    const result = db.prepare('INSERT INTO organizations (name) VALUES (?)').run(name.trim());
    const org = db.prepare('SELECT * FROM organizations WHERE id = ?').get(result.lastInsertRowid);
    return res.status(201).json(org);
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Organization name already exists' });
    }
    throw err;
  }
});

// GET /api/super-admin/organizations
router.get('/organizations', requireSuperAdmin, (req, res) => {
  const orgs = db.prepare(`
    SELECT
      o.*,
      COUNT(DISTINCT CASE WHEN u.role = 'org_admin' THEN u.id END) AS admin_count,
      COUNT(DISTINCT CASE WHEN u.role = 'end_user'  THEN u.id END) AS user_count,
      COUNT(DISTINCT f.id) AS flag_count
    FROM organizations o
    LEFT JOIN users u ON u.org_id = o.id
    LEFT JOIN feature_flags f ON f.org_id = o.id
    GROUP BY o.id
    ORDER BY o.created_at DESC
  `).all();
  return res.json(orgs);
});

// GET /api/super-admin/stats
router.get('/stats', requireSuperAdmin, (req, res) => {
  const stats = {
    orgs:   db.prepare('SELECT COUNT(*) as c FROM organizations').get().c,
    admins: db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'org_admin'").get().c,
    users:  db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'end_user'").get().c,
    flags:  db.prepare('SELECT COUNT(*) as c FROM feature_flags').get().c,
  };
  return res.json(stats);
});

module.exports = router;
