const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || process.env.MONGO_URL || 'mongodb://localhost:27017/sido';
const JWT_SECRET = process.env.JWT_SECRET || 'sido-design-secret-key-2026';

// ══════════════════════════════════
//  Mongoose Models
// ══════════════════════════════════

// User
const userSchema = new mongoose.Schema({
  username:  { type: String, required: true, unique: true },
  password:  { type: String, required: true },
  name:      { type: String, default: '' },
  role:      { type: String, enum: ['admin', 'user'], default: 'user' },
  active:    { type: Boolean, default: true },
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.comparePassword = function(pw) {
  return bcrypt.compare(pw, this.password);
};

const User = mongoose.model('User', userSchema);

// Estimate
const estimateSchema = new mongoose.Schema({
  userId:        { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  clientName:    { type: String, default: '' },
  clientTitle:   { type: String, default: '대표님' },
  clientPhone:   { type: String, default: '' },
  siteAddr:      { type: String, default: '' },
  buildingType:  { type: String, default: '' },
  area:          { type: String, default: '' },
  estDate:       { type: String, default: '' },
  workPeriod:    { type: String, default: '' },
  companyName:   { type: String, default: '' },
  managerName:   { type: String, default: '' },
  managerPhone:  { type: String, default: '' },
  profitPct:     { type: String, default: '10' },
  discVal:       { type: String, default: '0' },
  discType:      { type: String, default: 'pct' },
  validDays:     { type: String, default: '30' },
  roundMode:     { type: String, default: 'auto' },
  roundSign:     { type: String, default: '+' },
  roundManualVal:{ type: String, default: '0' },
  design:        { type: String, default: 'classic' },
  items:         { type: mongoose.Schema.Types.Mixed, default: {} },
  catNotes:      { type: mongoose.Schema.Types.Mixed, default: {} },
  grandTotal:    { type: Number, default: 0 },
}, { timestamps: true, strict: false });

const Estimate = mongoose.model('Estimate', estimateSchema);

// PublicEstimate — 새 에디터 페이지(/editor) 전용. 로그인 없이 저장/조회.
// 기존 Estimate 컬렉션과 완전히 분리되어 서로 영향 없음.
const publicEstimateSchema = new mongoose.Schema({
  title:        { type: String, default: '' },
  code:         { type: String, default: '' },
  subtitle:     { type: String, default: '' },
  client:       { type: String, default: '' },
  scale:        { type: String, default: '' },
  site:         { type: String, default: '' },
  company:      { type: String, default: '' },
  manager:      { type: String, default: '' },
  phone:        { type: String, default: '' },
  estDate:      { type: String, default: '' },
  valid:        { type: String, default: '' },
  overview:     { type: String, default: '' },
  mgmtRate:     { type: mongoose.Schema.Types.Mixed, default: 4 },
  profitRate:   { type: mongoose.Schema.Types.Mixed, default: 10 },
  mgmtOverride: { type: mongoose.Schema.Types.Mixed, default: '' },
  mgmtNote:     { type: String, default: '' },
  vatRate:      { type: mongoose.Schema.Types.Mixed, default: 10 },
  rounding:     { type: mongoose.Schema.Types.Mixed, default: 0 },
  groups:       { type: mongoose.Schema.Types.Mixed, default: [] },
  notes:        { type: mongoose.Schema.Types.Mixed, default: [] },
  grandTotal:   { type: Number, default: 0 },
  editKey:      { type: String, default: '' }, // 작성자 식별용(선택)
}, { timestamps: true, strict: false });

const PublicEstimate = mongoose.model('PublicEstimate', publicEstimateSchema);

// ══════════════════════════════════
//  Middleware
// ══════════════════════════════════
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

// JWT 인증 미들웨어
function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '로그인이 필요합니다' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: '세션이 만료되었습니다' });
  }
}

// 관리자 전용 미들웨어
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: '관리자 권한이 필요합니다' });
  next();
}

// ══════════════════════════════════
//  Auth API
// ══════════════════════════════════

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: '아이디 또는 비밀번호가 잘못되었습니다' });
    if (!user.active) return res.status(403).json({ error: '비활성화된 계정입니다. 관리자에게 문의하세요' });
    const ok = await user.comparePassword(password);
    if (!ok) return res.status(401).json({ error: '아이디 또는 비밀번호가 잘못되었습니다' });
    const token = jwt.sign(
      { id: user._id, username: user.username, name: user.name, role: user.role },
      JWT_SECRET, { expiresIn: '7d' }
    );
    res.json({ token, user: { id: user._id, username: user.username, name: user.name, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/auth/me — 현재 사용자 정보
app.get('/api/auth/me', auth, async (req, res) => {
  res.json(req.user);
});

// ══════════════════════════════════
//  Admin API — 사용자 관리
// ══════════════════════════════════

// GET /api/admin/users — 사용자 목록
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 }).sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/users — 사용자 추가
app.post('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const { username, password, name, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: '아이디와 비밀번호는 필수입니다' });
    const exists = await User.findOne({ username });
    if (exists) return res.status(400).json({ error: '이미 존재하는 아이디입니다' });
    const user = await User.create({ username, password, name: name || '', role: role || 'user' });
    res.status(201).json({ id: user._id, username: user.username, name: user.name, role: user.role });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/users/:id — 사용자 수정
app.put('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    const updates = {};
    if (req.body.name !== undefined) updates.name = req.body.name;
    if (req.body.role !== undefined) updates.role = req.body.role;
    if (req.body.active !== undefined) updates.active = req.body.active;
    if (req.body.password) updates.password = await bcrypt.hash(req.body.password, 10);
    const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true }).select('-password');
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/users/:id — 사용자 삭제
app.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    if (req.params.id === req.user.id) return res.status(400).json({ error: '자신의 계정은 삭제할 수 없습니다' });
    await User.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════
//  Estimate API (인증 필요)
// ══════════════════════════════════

app.get('/api/estimates', auth, async (req, res) => {
  try {
    const filter = req.user.role === 'admin' ? {} : { userId: req.user.id };
    const list = await Estimate.find(filter, {
      clientName: 1, siteAddr: 1, estDate: 1,
      area: 1, grandTotal: 1, updatedAt: 1, userId: 1,
    }).sort({ updatedAt: -1 }).limit(100);
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/estimates/:id', auth, async (req, res) => {
  try {
    const doc = await Estimate.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Not found' });
    if (req.user.role !== 'admin' && String(doc.userId) !== req.user.id) {
      return res.status(403).json({ error: '권한이 없습니다' });
    }
    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/estimates', auth, async (req, res) => {
  try {
    req.body.userId = req.user.id;
    const doc = await Estimate.create(req.body);
    res.status(201).json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/estimates/:id', auth, async (req, res) => {
  try {
    const doc = await Estimate.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Not found' });
    if (req.user.role !== 'admin' && String(doc.userId) !== req.user.id) {
      return res.status(403).json({ error: '권한이 없습니다' });
    }
    const updated = await Estimate.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/estimates/:id', auth, async (req, res) => {
  try {
    const doc = await Estimate.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Not found' });
    if (req.user.role !== 'admin' && String(doc.userId) !== req.user.id) {
      return res.status(403).json({ error: '권한이 없습니다' });
    }
    await Estimate.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════
//  Public Estimate API — 새 에디터 페이지 전용 (인증 불필요)
// ══════════════════════════════════

// 목록 (간단 필드만)
app.get('/api/public-estimates', async (req, res) => {
  try {
    const list = await PublicEstimate.find({}, {
      title: 1, site: 1, client: 1, estDate: 1, grandTotal: 1, updatedAt: 1,
    }).sort({ updatedAt: -1 }).limit(200);
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 단건 조회
app.get('/api/public-estimates/:id', async (req, res) => {
  try {
    const doc = await PublicEstimate.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 새로 저장
app.post('/api/public-estimates', async (req, res) => {
  try {
    const doc = await PublicEstimate.create(req.body);
    res.status(201).json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 수정
app.put('/api/public-estimates/:id', async (req, res) => {
  try {
    const updated = await PublicEstimate.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 삭제
app.delete('/api/public-estimates/:id', async (req, res) => {
  try {
    await PublicEstimate.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════
//  SPA Fallback
// ══════════════════════════════════

// 새 에디터 페이지 — 깔끔한 URL(/editor) 지원
app.get(['/editor', '/editor.html'], (req, res) => {
  res.sendFile(path.join(__dirname, 'editor.html'));
});

app.get('*', (req, res) => {
  const pubPath = path.join(__dirname, 'public', 'index.html');
  const rootPath = path.join(__dirname, 'index.html');
  if (fs.existsSync(pubPath)) res.sendFile(pubPath);
  else if (fs.existsSync(rootPath)) res.sendFile(rootPath);
  else res.status(404).send('index.html not found');
});

// ══════════════════════════════════
//  Start + Admin Seed
// ══════════════════════════════════
async function seedAdmin() {
  const exists = await User.findOne({ username: 'ysnao0923' });
  if (!exists) {
    await User.create({
      username: 'ysnao0923',
      password: 'edinsoncavani7*',
      name: '관리자',
      role: 'admin',
    });
    console.log('Admin account created: ysnao0923');
  }
}

mongoose.connect(MONGO_URI)
  .then(async () => {
    console.log('MongoDB connected');
    await seedAdmin();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });
