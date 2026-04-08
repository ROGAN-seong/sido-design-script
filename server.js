const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');

// ── Mongoose Model (inline) ──
const estimateSchema = new mongoose.Schema({
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
  grandTotal:    { type: Number, default: 0 },
}, { timestamps: true });
const Estimate = mongoose.model('Estimate', estimateSchema);

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || process.env.MONGO_URL || 'mongodb://localhost:27017/sido';

// Middleware
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── API Routes ──

// GET /api/estimates — 목록 (최신순, 요약만)
app.get('/api/estimates', async (req, res) => {
  try {
    const list = await Estimate.find({}, {
      clientName: 1, siteAddr: 1, estDate: 1,
      area: 1, grandTotal: 1, updatedAt: 1,
    }).sort({ updatedAt: -1 }).limit(100);
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/estimates/:id — 단건 조회
app.get('/api/estimates/:id', async (req, res) => {
  try {
    const doc = await Estimate.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/estimates — 신규 저장
app.post('/api/estimates', async (req, res) => {
  try {
    const doc = await Estimate.create(req.body);
    res.status(201).json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/estimates/:id — 수정
app.put('/api/estimates/:id', async (req, res) => {
  try {
    const doc = await Estimate.findByIdAndUpdate(
      req.params.id, req.body, { new: true, runValidators: true }
    );
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/estimates/:id — 삭제
app.delete('/api/estimates/:id', async (req, res) => {
  try {
    const doc = await Estimate.findByIdAndDelete(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// SPA fallback — public/index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ──
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('MongoDB connected');
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });
