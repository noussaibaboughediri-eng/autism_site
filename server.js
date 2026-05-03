require('dotenv').config();
const express    = require('express');
const mongoose   = require('mongoose');
const cors       = require('cors');
const authRoutes = require('./routes/auth');

const app = express();

app.use(cors());
app.use(express.json());
app.use('/api/auth', authRoutes);

mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('✅ اتصلنا بقاعدة البيانات بنجاح');
    app.listen(process.env.PORT, () => {
      console.log(`🚀 الخادم يعمل على http://localhost:${process.env.PORT}`);
    });
  })
  .catch(err => {
    console.error('❌ خطأ في الاتصال بقاعدة البيانات:', err.message);
  });
  