const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  firstName:            { type: String, required: true },
  lastName:             { type: String, required: true },
  relationship:         { type: String, required: true },
  phone:                { type: String, required: true },
  email:                { type: String, required: true, unique: true },
  password:             { type: String, required: true },
  childName:            { type: String, required: true },
  birthDate:            { type: String, required: true },
  gender:               { type: String, required: true },
  city:                 { type: String, required: true },
  autismLevel:          { type: String, required: true },
  diagnosisDate:        { type: String, required: true },
  doctorName:           { type: String, required: true },
  hospital:             { type: String, required: true },
  hasTherapy:           { type: String, required: true },
  therapyType:          { type: String, default: '' },
  speakingAbility:      { type: String, default: '' },
  goesToSchool:         { type: String, default: '' },
  notes:                { type: String, default: '' },
  medicalCertificate:   { type: String, default: '' },   // مسار الملف على الخادم
  certFileName:         { type: String, default: '' },   // اسم الملف الأصلي
  status: {
    type: String,
    enum: ['pending', 'accepted', 'rejected'],
    default: 'pending'
  }
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);