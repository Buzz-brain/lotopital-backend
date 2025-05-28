const mongoose = require('mongoose');

const adminSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    required: true,
    enum: ['admin', 'user'],
    default: 'admin',
  },
  verified: {
    type: Boolean,
    default: false,
  },
  lastVerificationSent: {
    type: Date,
    default: null,
  },
  verificationFailed: Boolean,
  resetToken: String,
  resetTokenExpiration: Date,
  },
  { timestamps: true }
);

const Admin = mongoose.model('Admin', adminSchema);

module.exports = Admin;
