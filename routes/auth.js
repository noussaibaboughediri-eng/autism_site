const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const User = require('../models/User');

// ─── Multer: memory storage (بدون حفظ على القرص) ─────────────
const fileFilter = (req, file, cb) => {
  const allowed = ['image/jpeg', 'image/jpg', 'image/png', 'application/pdf'];
  allowed.includes(file.mimetype)
    ? cb(null, true)
    : cb(new Error('نوع الملف غير مدعوم'), false);
};

const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }
});

// ─── Nodemailer ───────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

async function sendEmail(to, subject, html) {
  await transporter.sendMail({
    from: `"منصة أطفال التوحد" <${process.env.EMAIL_USER}>`,
    to, subject, html
  });
}

// ─── Register ─────────────────────────────────────────────────
router.post('/register', upload.single('medicalCertificate'), async (req, res) => {
  try {
    const {
      firstName, lastName, relationship, phone, email, password,
      childName, birthDate, gender, city,
      autismLevel, diagnosisDate, doctorName, hospital,
      hasTherapy, therapyType, speakingAbility, goesToSchool, notes
    } = req.body;

    if (!req.file) {
      return res.status(400).json({ message: 'يرجى إرفاق الشهادة الطبية للتشخيص' });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ message: 'هذا البريد مسجل مسبقاً' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await new User({
      firstName, lastName, relationship, phone, email,
      password: hashedPassword,
      childName, birthDate, gender, city,
      autismLevel, diagnosisDate, doctorName, hospital,
      hasTherapy, therapyType, speakingAbility, goesToSchool, notes,
      medicalCertificate: req.file.buffer.toString('base64'),
      medicalCertificateType: req.file.mimetype,
      certFileName: req.file.originalname
    }).save();

    res.status(201).json({ message: 'تم إرسال طلبك بنجاح، انتظر موافقة الإدارة' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// ─── Login ────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'البريد أو كلمة المرور خاطئة' });
    if (user.status === 'pending') return res.status(403).json({ message: 'طلبك لا يزال قيد المراجعة' });
    if (user.status === 'rejected') return res.status(403).json({ message: 'تم رفض طلبك' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: 'البريد أو كلمة المرور خاطئة' });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        firstName: user.firstName, lastName: user.lastName,
        email: user.email, childName: user.childName,
        birthDate: user.birthDate, gender: user.gender,
        city: user.city, autismLevel: user.autismLevel,
        diagnosisDate: user.diagnosisDate, doctorName: user.doctorName,
        hospital: user.hospital, hasTherapy: user.hasTherapy,
        therapyType: user.therapyType, speakingAbility: user.speakingAbility,
        goesToSchool: user.goesToSchool, notes: user.notes,
        certFileName: user.certFileName
      }
    });
  } catch (err) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// ─── Admin Login ──────────────────────────────────────────────
router.post('/admin-login', (req, res) => {
  const { email, password } = req.body;
  if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1d' });
    return res.json({ token });
  }
  res.status(401).json({ message: 'بيانات الأدمن خاطئة' });
});

// ─── Admin Auth Middleware ────────────────────────────────────
function adminAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'غير مصرح' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') throw new Error();
    next();
  } catch {
    res.status(401).json({ message: 'توكن غير صالح' });
  }
}

// ─── Get All Users ────────────────────────────────────────────
router.get('/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find({}, '-password -medicalCertificate').sort({ createdAt: -1 });
    res.json(users);
  } catch {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// ─── عرض الشهادة الطبية ───────────────────────────────────────
router.get('/certificate/:userId', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1] || req.query.token;
  if (!token) return res.status(401).json({ message: 'غير مصرح' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(401).json({ message: 'غير مصرح' });
  } catch {
    return res.status(401).json({ message: 'توكن غير صالح' });
  }

  try {
    const user = await User.findById(req.params.userId);
    if (!user || !user.medicalCertificate) {
      return res.status(404).json({ message: 'الملف غير موجود' });
    }

    const img = Buffer.from(user.medicalCertificate, 'base64');
    res.set('Content-Type', user.medicalCertificateType || 'image/jpeg');
    res.set('Content-Disposition', `inline; filename="${user.certFileName || 'certificate'}"`);
    res.send(img);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// ─── قبول المستخدم ────────────────────────────────────────────
router.patch('/users/:id/accept', adminAuth, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, { status: 'accepted' }, { new: true });
    if (!user) return res.status(404).json({ message: 'المستخدم غير موجود' });
    await sendEmail(user.email, '🎉 تم قبول طلب تسجيل طفلك!', `
      <div dir="rtl" style="font-family:Arial;max-width:500px;margin:auto;padding:24px;border:1px solid #eee;border-radius:12px;">
        <h2 style="color:#22c55e;">مرحباً ${user.firstName} ${user.lastName} 👋</h2>
        <p>تم قبول طلب تسجيل طفلك <strong>${user.childName}</strong>.</p>
        <p style="color:#888;font-size:13px;">فريق منصة أطفال التوحد 🧩</p>
      </div>
    `);
    res.json({ message: 'تم القبول وإرسال الإيميل بنجاح' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// ─── رفض المستخدم ─────────────────────────────────────────────
router.patch('/users/:id/reject', adminAuth, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, { status: 'rejected' }, { new: true });
    if (!user) return res.status(404).json({ message: 'المستخدم غير موجود' });
    await sendEmail(user.email, 'بشأن طلب تسجيل طفلك', `
      <div dir="rtl" style="font-family:Arial;max-width:500px;margin:auto;padding:24px;border:1px solid #eee;border-radius:12px;">
        <h2 style="color:#ef4444;">عزيزي ${user.firstName} ${user.lastName}</h2>
        <p>تم رفض طلب تسجيل طفلك <strong>${user.childName}</strong>.</p>
        <p style="color:#888;font-size:13px;">فريق منصة أطفال التوحد 🧩</p>
      </div>
    `);
    res.json({ message: 'تم الرفض وإرسال الإيميل بنجاح' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// ─── Stats ────────────────────────────────────────────────────
router.get('/stats', async (req, res) => {
  try {
    const total = await User.countDocuments();
    const accepted = await User.countDocuments({ status: 'accepted' });
    const pending = await User.countDocuments({ status: 'pending' });
    res.json({ total, accepted, pending });
  } catch {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// ─── توليد رمز VR ─────────────────────────────────────────────
router.post('/vr-token', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'غير مصرح' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(404).json({ message: 'المستخدم غير موجود' });

    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let vrToken = '';
    for (let i = 0; i < 6; i++)
      vrToken += chars[Math.floor(Math.random() * chars.length)];

    user.vrToken = vrToken;
    user.vrTokenExpiry = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    res.json({ vrToken });
  } catch {
    res.status(401).json({ message: 'توكن غير صالح' });
  }
});

// ─── التحقق من رمز VR ────────────────────────────────────────
router.post('/verify-vr-token', async (req, res) => {
  const { vrToken } = req.body;
  if (!vrToken) return res.status(400).json({ message: 'الرمز مطلوب' });
  try {
    const user = await User.findOne({ vrToken: vrToken.toUpperCase() });
    if (!user) return res.status(401).json({ message: 'رمز خاطئ' });
    if (user.vrTokenExpiry < new Date())
      return res.status(401).json({ message: 'انتهت صلاحية الرمز' });

    const sessionNumber = (user.vrSessions ? user.vrSessions.length : 0) + 1;
    user.vrSessions.push({ sessionNumber, date: new Date() });
    await user.save();

    res.json({ success: true, childName: user.childName, userId: user._id, sessionNumber });
  } catch {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// ─── حذف المستخدم ─────────────────────────────────────────────
router.delete('/users/:id', adminAuth, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ message: 'المستخدم غير موجود' });
    res.json({ message: 'تم حذف المستخدم بنجاح' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

module.exports = router;
