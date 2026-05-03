const express    = require('express');
const router     = express.Router();
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer     = require('multer');
const path       = require('path');
const fs         = require('fs');
const User       = require('../models/User');

// ─── إعداد multer لرفع الشهادة الطبية ───────────────────────
const uploadDir = path.join(__dirname, '../uploads/certificates');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename:    (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e6);
    const ext    = path.extname(file.originalname);
    cb(null, 'cert-' + unique + ext);
  }
});

const fileFilter = (req, file, cb) => {
  const allowed = ['image/jpeg', 'image/jpg', 'image/png', 'application/pdf'];
  allowed.includes(file.mimetype)
    ? cb(null, true)
    : cb(new Error('نوع الملف غير مدعوم'), false);
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }   // 5 ميغابايت
});

// ─── إعداد الإيميل ───────────────────────────────────────────
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

// ─── تسجيل مشترك جديد ────────────────────────────────────────
router.post('/register', upload.single('medicalCertificate'), async (req, res) => {
  try {
    const {
      firstName, lastName, relationship, phone, email, password,
      childName, birthDate, gender, city,
      autismLevel, diagnosisDate, doctorName, hospital,
      hasTherapy, therapyType, speakingAbility, goesToSchool, notes
    } = req.body;

    // التحقق من وجود الشهادة الطبية
    if (!req.file) {
      return res.status(400).json({ message: 'يرجى إرفاق الشهادة الطبية للتشخيص' });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      // حذف الملف المرفوع إن كان البريد مكرراً
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ message: 'هذا البريد مسجل مسبقاً' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await new User({
      firstName, lastName, relationship, phone, email,
      password: hashedPassword,
      childName, birthDate, gender, city,
      autismLevel, diagnosisDate, doctorName, hospital,
      hasTherapy, therapyType, speakingAbility, goesToSchool, notes,
      medicalCertificate: req.file.filename,        // اسم الملف المحفوظ
      certFileName:       req.file.originalname     // الاسم الأصلي للعرض
    }).save();

    res.status(201).json({ message: 'تم إرسال طلبك بنجاح، انتظر موافقة الإدارة' });

  } catch (err) {
    // حذف الملف عند أي خطأ
    if (req.file) fs.unlink(req.file.path, () => {});
    console.error(err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// ─── تسجيل دخول المشترك ──────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'البريد أو كلمة المرور خاطئة' });
    }
    if (user.status === 'pending') {
      return res.status(403).json({ message: 'طلبك لا يزال قيد المراجعة' });
    }
    if (user.status === 'rejected') {
      return res.status(403).json({ message: 'تم رفض طلبك' });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ message: 'البريد أو كلمة المرور خاطئة' });
    }

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        firstName:          user.firstName,
        lastName:           user.lastName,
        email:              user.email,
        childName:          user.childName,
        birthDate:          user.birthDate,
        gender:             user.gender,
        city:               user.city,
        autismLevel:        user.autismLevel,
        diagnosisDate:      user.diagnosisDate,
        doctorName:         user.doctorName,
        hospital:           user.hospital,
        hasTherapy:         user.hasTherapy,
        therapyType:        user.therapyType,
        speakingAbility:    user.speakingAbility,
        goesToSchool:       user.goesToSchool,
        notes:              user.notes,
        certFileName:       user.certFileName,
        medicalCertificate: user.medicalCertificate
      }
    });

  } catch (err) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// ─── تسجيل دخول الأدمن ───────────────────────────────────────
router.post('/admin-login', (req, res) => {
  const { email, password } = req.body;
  if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1d' });
    return res.json({ token });
  }
  res.status(401).json({ message: 'بيانات الأدمن خاطئة' });
});

// ─── التحقق من توكن الأدمن ───────────────────────────────────
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

// ─── جلب جميع المستخدمين (للأدمن) ───────────────────────────
router.get('/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find({}, '-password').sort({ createdAt: -1 });
    res.json(users);
  } catch {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// ─── تحميل الشهادة الطبية (للأدمن) ──────────────────────────
// يقبل التوكن من header أو من query string (?token=...)
router.get('/certificate/:filename', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1] || req.query.token;
  if (!token) return res.status(401).json({ message: 'غير مصرح' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(401).json({ message: 'غير مصرح' });
  } catch {
    return res.status(401).json({ message: 'توكن غير صالح' });
  }

  const filePath = path.join(__dirname, '../uploads/certificates', req.params.filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ message: 'الملف غير موجود' });
  }
  res.sendFile(filePath);
});

// ─── قبول طلب ────────────────────────────────────────────────
router.patch('/users/:id/accept', adminAuth, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id, { status: 'accepted' }, { new: true }
    );
    if (!user) return res.status(404).json({ message: 'المستخدم غير موجود' });

    await sendEmail(user.email, '🎉 تم قبول طلب تسجيل طفلك!', `
      <div dir="rtl" style="font-family:Arial;max-width:500px;margin:auto;padding:24px;border:1px solid #eee;border-radius:12px;">
        <h2 style="color:#22c55e;">مرحباً ${user.firstName} ${user.lastName} 👋</h2>
        <p style="font-size:16px;line-height:1.8;">
          يسعدنا إبلاغك بأنه <strong>تم قبول طلب تسجيل</strong> طفلك
          <strong>${user.childName}</strong> في منصتنا.
        </p>
        <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">
        <p><strong>درجة التوحد:</strong> ${user.autismLevel}</p>
        <p><strong>الطبيب المشخِّص:</strong> ${user.doctorName}</p>
        <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">
        <p>يمكنك الآن تسجيل الدخول باستخدام بريدك الإلكتروني وكلمة المرور.</p>
        <p style="color:#888;font-size:13px;margin-top:20px;">فريق منصة أطفال التوحد 🧩</p>
      </div>
    `);

    res.json({ message: 'تم القبول وإرسال الإيميل بنجاح' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// ─── رفض طلب ─────────────────────────────────────────────────
router.patch('/users/:id/reject', adminAuth, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id, { status: 'rejected' }, { new: true }
    );
    if (!user) return res.status(404).json({ message: 'المستخدم غير موجود' });

    await sendEmail(user.email, 'بشأن طلب تسجيل طفلك', `
      <div dir="rtl" style="font-family:Arial;max-width:500px;margin:auto;padding:24px;border:1px solid #eee;border-radius:12px;">
        <h2 style="color:#ef4444;">عزيزي ${user.firstName} ${user.lastName}</h2>
        <p style="font-size:16px;line-height:1.8;">
          نأسف لإبلاغك بأنه <strong>تم رفض طلب تسجيل</strong> طفلك
          <strong>${user.childName}</strong>.
        </p>
        <p>إذا كنت تعتقد أن هذا خطأ، يرجى التواصل معنا مباشرة.</p>
        <p style="color:#888;font-size:13px;margin-top:20px;">فريق منصة أطفال التوحد 🧩</p>
      </div>
    `);

    res.json({ message: 'تم الرفض وإرسال الإيميل بنجاح' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// ─── إحصائيات عامة (بدون توثيق) ─────────────────────────────
router.get('/stats', async (req, res) => {
  try {
    const total    = await User.countDocuments();
    const accepted = await User.countDocuments({ status: 'accepted' });
    const pending  = await User.countDocuments({ status: 'pending' });
    res.json({ total, accepted, pending });
  } catch {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

module.exports = router;


