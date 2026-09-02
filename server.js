'use strict';

/* ============================================================
 * BMA - Digital Payment Platform
 * Single-file backend (server.js). See README output for deploy notes.
 * ============================================================ */

/* ============================================================
 * SECTION: CONFIGURATION
 * ============================================================ */
require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const mongoSanitize = require('express-mongo-sanitize');
const { body, param, validationResult } = require('express-validator');
const { doubleCsrf } = require('csrf-csrf');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');

const IS_PROD = process.env.NODE_ENV === 'production';
const APP_URL = process.env.APP_URL || 'http://localhost:3000';
const DEFAULT_COIN_RATE = 16; // 1 BMC = 16 BDT (fallback only; authoritative value lives in SystemSetting)

const REQUIRED_ENV = ['MONGODB_URI', 'SESSION_SECRET', 'ENCRYPTION_KEY', 'ADMIN_EMAIL', 'ADMIN_PASSWORD'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    // eslint-disable-next-line no-console
    console.error(`[BMA CONFIG ERROR] Required environment variable ${key} is not set. ` +
      `The application cannot start safely without it. Please configure it in your deployment environment.`);
    if (!process.env.VERCEL) process.exit(1);
  }
}

/* ============================================================
 * SECTION: DATABASE (serverless-safe connection caching)
 * ============================================================ */
let cachedConnection = null;
async function connectDB() {
  if (cachedConnection && mongoose.connection.readyState === 1) return cachedConnection;
  if (!process.env.MONGODB_URI) {
    throw new Error('MONGODB_URI is not configured.');
  }
  mongoose.set('strictQuery', true);
  cachedConnection = await mongoose.connect(process.env.MONGODB_URI, {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 8000,
  });
  // eslint-disable-next-line no-console
  console.log('[BMA] MongoDB connected');
  return cachedConnection;
}

/* ============================================================
 * SECTION: SCHEMAS
 * ============================================================ */
const { Schema } = mongoose;
const Decimal128 = Schema.Types.Decimal128;

function dec(v) { return mongoose.Types.Decimal128.fromString(String(v)); }
function decToNum(d) { return d == null ? 0 : parseFloat(d.toString()); }

const UserSchema = new Schema({
  full_name: { type: String, required: true, trim: true, maxlength: 120 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
  phone: { type: String, required: true, unique: true, trim: true, index: true },
  password_hash: { type: String, required: true },
  role: { type: String, enum: ['user', 'merchant', 'admin'], required: true, default: 'user', index: true },
  status: { type: String, enum: ['active', 'pending', 'suspended', 'frozen', 'deleted'], default: 'active', index: true },
  profile_picture: { type: String, default: null },
  address: { type: String, default: '' },
  failed_login_attempts: { type: Number, default: 0 },
  lock_until: { type: Date, default: null },
  reset_token_hash: { type: String, default: null },
  reset_token_expires: { type: Date, default: null },
  last_login: { type: Date, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const User = mongoose.model('User', UserSchema);

const MerchantSchema = new Schema({
  user_id: { type: Schema.Types.ObjectId, ref: 'User', required: true, unique: true, index: true },
  merchant_ref: { type: String, required: true, unique: true, index: true },
  business_name: { type: String, required: true, trim: true },
  owner_name: { type: String, required: true, trim: true },
  business_type: { type: String, default: '' },
  business_address: { type: String, default: '' },
  phone: { type: String, default: '' },
  email: { type: String, default: '' },
  status: { type: String, enum: ['Pending', 'Under Review', 'Approved', 'Rejected', 'Suspended', 'Frozen'], default: 'Pending', index: true },
  settlement_account_masked: { type: String, default: null },
  auto_settlement: {
    enabled: { type: Boolean, default: false },
    frequency: { type: String, enum: ['Daily', 'Weekly', 'Monthly'], default: 'Weekly' },
    min_amount: { type: Number, default: 100 },
  },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const Merchant = mongoose.model('Merchant', MerchantSchema);

const WalletSchema = new Schema({
  owner_id: { type: Schema.Types.ObjectId, required: true, index: true },
  owner_type: { type: String, enum: ['user', 'merchant_pending', 'merchant_available', 'escrow', 'platform_reserve'], required: true },
  currency: { type: String, default: 'BMC' },
  status: { type: String, enum: ['active', 'frozen'], default: 'active' },
  balance_minor_cache: { type: Number, default: 0 }, // authoritative cache, written atomically with ledger; verifiable via ledger replay
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
WalletSchema.index({ owner_id: 1, owner_type: 1 }, { unique: true });
const Wallet = mongoose.model('Wallet', WalletSchema);

const LedgerEntrySchema = new Schema({
  transaction_id: { type: String, required: true, index: true },
  wallet_id: { type: Schema.Types.ObjectId, ref: 'Wallet', required: true, index: true },
  entry_type: { type: String, required: true }, // Deposit, Payment, Refund, Settlement, Adjustment, Escrow
  direction: { type: String, enum: ['debit', 'credit'], required: true },
  amount_bmc: { type: Decimal128, required: true },
  amount_bdt: { type: Decimal128, required: true },
  rate_bdt: { type: Number, required: true },
  balance_before: { type: Number, required: true },
  balance_after: { type: Number, required: true },
  previous_hash: { type: String, required: true },
  current_hash: { type: String, required: true },
  reference: { type: String, default: '' },
  created_at: { type: Date, default: Date.now },
});
LedgerEntrySchema.index({ wallet_id: 1, created_at: 1 });
const LedgerEntry = mongoose.model('LedgerEntry', LedgerEntrySchema);

const TransactionSchema = new Schema({
  tx_id: { type: String, required: true, unique: true, index: true },
  type: { type: String, enum: ['Deposit', 'Payment', 'Refund', 'Settlement', 'Adjustment'], required: true },
  user_id: { type: Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  merchant_id: { type: Schema.Types.ObjectId, ref: 'Merchant', default: null, index: true },
  amount_bmc: { type: Decimal128, required: true },
  amount_bdt: { type: Decimal128, required: true },
  rate_bdt: { type: Number, required: true },
  status: { type: String, enum: ['Pending', 'Processing', 'Completed', 'Failed', 'Reversed'], default: 'Pending', index: true },
  reference: { type: String, default: '' },
  metadata: { type: Schema.Types.Mixed, default: {} },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const Transaction = mongoose.model('Transaction', TransactionSchema);

const DepositSchema = new Schema({
  reference: { type: String, required: true, unique: true, index: true },
  user_id: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  amount_bdt: { type: Decimal128, required: true },
  amount_bmc: { type: Decimal128, required: true },
  rate_bdt: { type: Number, required: true },
  provider: { type: String, default: '' },
  provider_payment_id: { type: String, default: null },
  status: { type: String, enum: ['Pending', 'Processing', 'Completed', 'Failed'], default: 'Pending', index: true },
  idempotency_key: { type: String, default: null },
  tx_id: { type: String, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const Deposit = mongoose.model('Deposit', DepositSchema);

const PaymentSchema = new Schema({
  reference: { type: String, required: true, unique: true, index: true },
  user_id: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  merchant_id: { type: Schema.Types.ObjectId, ref: 'Merchant', required: true, index: true },
  order_id: { type: Schema.Types.ObjectId, ref: 'Order', default: null },
  amount_bmc: { type: Decimal128, required: true },
  amount_bdt: { type: Decimal128, required: true },
  rate_bdt: { type: Number, required: true },
  status: { type: String, enum: ['Pending', 'Processing', 'Completed', 'Failed', 'Reversed'], default: 'Pending', index: true },
  idempotency_key: { type: String, default: null },
  tx_id: { type: String, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const Payment = mongoose.model('Payment', PaymentSchema);

const OrderItemSchema = new Schema({
  order_id: { type: Schema.Types.ObjectId, ref: 'Order', index: true },
  name: { type: String, required: true },
  quantity: { type: Number, required: true, min: 1 },
  unit_price_bmc: { type: Decimal128, required: true },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const OrderItem = mongoose.model('OrderItem', OrderItemSchema);

const OrderSchema = new Schema({
  order_id: { type: String, required: true, unique: true, index: true },
  user_id: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  merchant_id: { type: Schema.Types.ObjectId, ref: 'Merchant', required: true, index: true },
  items: [{ type: Schema.Types.ObjectId, ref: 'OrderItem' }],
  subtotal_bmc: { type: Decimal128, required: true },
  discount_bmc: { type: Decimal128, default: dec(0) },
  total_bmc: { type: Decimal128, required: true },
  total_bdt: { type: Decimal128, required: true },
  status: { type: String, enum: ['Pending', 'Confirmed', 'Processing', 'Ready', 'Completed', 'Cancelled', 'Disputed'], default: 'Pending' },
  payment_status: { type: String, enum: ['Pending', 'Processing', 'Completed', 'Failed', 'Refunded'], default: 'Pending' },
  fulfillment_status: { type: String, enum: ['Pending', 'Processing', 'Ready', 'Completed', 'Cancelled'], default: 'Pending' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const Order = mongoose.model('Order', OrderSchema);

const EscrowSchema = new Schema({
  payment_id: { type: Schema.Types.ObjectId, ref: 'Payment', required: true, index: true },
  order_id: { type: Schema.Types.ObjectId, ref: 'Order', default: null },
  merchant_id: { type: Schema.Types.ObjectId, ref: 'Merchant', required: true, index: true },
  amount_bmc: { type: Decimal128, required: true },
  status: { type: String, enum: ['Held', 'Released', 'Refunded'], default: 'Held', index: true },
  released_at: { type: Date, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const Escrow = mongoose.model('Escrow', EscrowSchema);

const RefundSchema = new Schema({
  ref: { type: String, required: true, unique: true, index: true },
  user_id: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  merchant_id: { type: Schema.Types.ObjectId, ref: 'Merchant', default: null },
  original_tx_id: { type: String, required: true, index: true },
  amount_bmc: { type: Decimal128, required: true },
  amount_bdt: { type: Decimal128, required: true },
  reason: { type: String, required: true },
  status: { type: String, enum: ['Requested', 'Approved', 'Processing', 'Completed', 'Rejected', 'Failed', 'Reversed'], default: 'Requested', index: true },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const Refund = mongoose.model('Refund', RefundSchema);

const DisputeSchema = new Schema({
  ref: { type: String, required: true, unique: true, index: true },
  user_id: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  merchant_id: { type: Schema.Types.ObjectId, ref: 'Merchant', default: null },
  tx_id: { type: String, required: true, index: true },
  reason: { type: String, required: true },
  merchant_response: { type: String, default: null },
  status: { type: String, enum: ['Open', 'Under Review', 'Merchant Responded', 'Approved', 'Rejected', 'Resolved'], default: 'Open', index: true },
  resolution: { type: String, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const Dispute = mongoose.model('Dispute', DisputeSchema);

const SettlementSchema = new Schema({
  ref: { type: String, required: true, unique: true, index: true },
  merchant_id: { type: Schema.Types.ObjectId, ref: 'Merchant', required: true, index: true },
  amount_bmc: { type: Decimal128, required: true },
  amount_bdt: { type: Decimal128, required: true },
  rate_bdt: { type: Number, required: true },
  status: { type: String, enum: ['Pending', 'Processing', 'Completed', 'Failed', 'Reversed', 'On Hold', 'Under Review'], default: 'Pending', index: true },
  provider: { type: String, default: '' },
  provider_settlement_id: { type: String, default: null },
  idempotency_key: { type: String, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const Settlement = mongoose.model('Settlement', SettlementSchema);

const KYCSchema = new Schema({
  user_id: { type: Schema.Types.ObjectId, ref: 'User', required: true, unique: true, index: true },
  full_name: { type: String, default: '' },
  date_of_birth: { type: String, default: '' },
  phone: { type: String, default: '' },
  email: { type: String, default: '' },
  address: { type: String, default: '' },
  identification_type: { type: String, default: '' },
  identification_number: { type: String, default: '' },
  document_metadata: { type: Schema.Types.Mixed, default: {} },
  status: { type: String, enum: ['Not Started', 'Pending', 'Under Review', 'Verified', 'Rejected', 'Expired'], default: 'Not Started', index: true },
  submitted_at: { type: Date, default: null },
  verified_at: { type: Date, default: null },
  reviewed_by: { type: Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const KYC = mongoose.model('KYC', KYCSchema);

const KYBSchema = new Schema({
  merchant_id: { type: Schema.Types.ObjectId, ref: 'Merchant', required: true, unique: true, index: true },
  business_name: { type: String, default: '' },
  owner_name: { type: String, default: '' },
  business_type: { type: String, default: '' },
  business_address: { type: String, default: '' },
  phone: { type: String, default: '' },
  email: { type: String, default: '' },
  trade_license_metadata: { type: Schema.Types.Mixed, default: {} },
  business_document_metadata: { type: Schema.Types.Mixed, default: {} },
  settlement_account_metadata: { type: Schema.Types.Mixed, default: {} },
  status: { type: String, enum: ['Pending', 'Under Review', 'Approved', 'Rejected', 'Suspended'], default: 'Pending', index: true },
  submitted_at: { type: Date, default: null },
  verified_at: { type: Date, default: null },
  reviewed_by: { type: Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const KYB = mongoose.model('KYB', KYBSchema);

const NotificationSchema = new Schema({
  owner_id: { type: Schema.Types.ObjectId, required: true, index: true },
  owner_role: { type: String, enum: ['user', 'merchant', 'admin'], required: true },
  type: { type: String, required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  read: { type: Boolean, default: false, index: true },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const Notification = mongoose.model('Notification', NotificationSchema);

const AuditLogSchema = new Schema({
  actor_id: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  actor_role: { type: String, default: 'system' },
  action: { type: String, required: true },
  target_type: { type: String, default: '' },
  target_id: { type: String, default: '' },
  ip: { type: String, default: '' },
  user_agent: { type: String, default: '' },
  metadata: { type: Schema.Types.Mixed, default: {} },
  created_at: { type: Date, default: Date.now },
});
const AuditLog = mongoose.model('AuditLog', AuditLogSchema);

const RiskAlertSchema = new Schema({
  ref: { type: String, required: true, unique: true, index: true },
  type: { type: String, required: true },
  subject_type: { type: String, default: '' },
  subject_id: { type: String, default: '' },
  severity: { type: String, enum: ['Normal', 'Flagged', 'Under Review', 'Blocked'], default: 'Flagged', index: true },
  status: { type: String, enum: ['Open', 'Under Review', 'Resolved'], default: 'Open', index: true },
  details: { type: Schema.Types.Mixed, default: {} },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const RiskAlert = mongoose.model('RiskAlert', RiskAlertSchema);

const SystemSettingSchema = new Schema({
  singleton: { type: String, default: 'main', unique: true },
  coin_rate_bdt: { type: Number, default: DEFAULT_COIN_RATE },
  minimum_deposit: { type: Number, default: 50 },
  maximum_deposit: { type: Number, default: 100000 },
  wallet_limit: { type: Number, default: 500000 },
  daily_payment_limit: { type: Number, default: 2000 },
  monthly_payment_limit: { type: Number, default: 20000 },
  merchant_settlement_minimum: { type: Number, default: 100 },
  risk_threshold: { type: Number, default: 5000 },
  maintenance_mode: { type: Boolean, default: false },
  registration_enabled: { type: Boolean, default: true },
  merchant_registration_enabled: { type: Boolean, default: true },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const SystemSetting = mongoose.model('SystemSetting', SystemSettingSchema);

const PaymentProviderSchema = new Schema({
  name: { type: String, required: true },
  is_active: { type: Boolean, default: false },
  mode: { type: String, enum: ['test', 'live'], default: 'test' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const PaymentProvider = mongoose.model('PaymentProvider', PaymentProviderSchema);

const SettlementProviderSchema = new Schema({
  name: { type: String, required: true },
  is_active: { type: Boolean, default: false },
  mode: { type: String, enum: ['test', 'live'], default: 'test' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const SettlementProvider = mongoose.model('SettlementProvider', SettlementProviderSchema);

const WebhookEventSchema = new Schema({
  provider: { type: String, required: true },
  event_id: { type: String, required: true },
  payload_hash: { type: String, required: true },
  processed: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now },
});
WebhookEventSchema.index({ provider: 1, event_id: 1 }, { unique: true });
const WebhookEvent = mongoose.model('WebhookEvent', WebhookEventSchema);

const ReconciliationSchema = new Schema({
  ref: { type: String, required: true, unique: true, index: true },
  ledger_total: { type: Number, required: true },
  provider_total: { type: Number, required: true },
  variance: { type: Number, required: true },
  status: { type: String, enum: ['Matched', 'Mismatch', 'Under Review', 'Resolved'], default: 'Matched', index: true },
  created_at: { type: Date, default: Date.now },
});
const Reconciliation = mongoose.model('Reconciliation', ReconciliationSchema);

const DeviceSessionSchema = new Schema({
  user_id: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  session_id: { type: String, required: true, unique: true },
  device: { type: String, default: 'Unknown device' },
  ip: { type: String, default: '' },
  user_agent: { type: String, default: '' },
  last_seen: { type: Date, default: Date.now },
  revoked: { type: Boolean, default: false, index: true },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
const DeviceSession = mongoose.model('DeviceSession', DeviceSessionSchema);

const IdempotencyKeySchema = new Schema({
  key: { type: String, required: true, unique: true, index: true },
  scope: { type: String, required: true },
  request_hash: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  response_snapshot: { type: Schema.Types.Mixed, default: null },
  created_at: { type: Date, default: Date.now },
});
const IdempotencyKey = mongoose.model('IdempotencyKey', IdempotencyKeySchema);

/* ============================================================
 * SECTION: SECURITY (helmet, rate limiting, sanitize, csrf)
 * ============================================================ */
const app = express();
app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(helmet({
  contentSecurityPolicy: false, // CDN assets used for Bootstrap/FontAwesome/Chart.js in views
}));
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: true, limit: '200kb' }));
app.use(cookieParser());
app.use(mongoSanitize());

const globalLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });
app.use(globalLimiter);

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  message: 'Too many attempts. Please try again later.' });

const financialLimiter = rateLimit({ windowMs: 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false,
  message: 'Too many requests. Please slow down.' });

app.use((req, res, next) => {
  connectDB().then(() => next()).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[BMA] DB connection error:', err.message);
    res.status(503).send('Service temporarily unavailable. Please try again shortly.');
  });
});

app.use(session({
  name: 'bma.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI, collectionName: 'sessions', ttl: 60 * 60 * 24 * 7 }),
  cookie: {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7,
  },
}));

const { doubleCsrfProtection, generateToken } = doubleCsrf({
  getSecret: () => process.env.ENCRYPTION_KEY,
  cookieName: IS_PROD ? '__Host-bma.csrf' : 'bma.csrf',
  cookieOptions: { httpOnly: true, sameSite: 'lax', secure: IS_PROD, path: '/' },
  getTokenFromRequest: (req) => req.body._csrf || req.headers['x-csrf-token'],
});

app.use((req, res, next) => {
  try {
    res.locals.csrfToken = generateToken(req, res);
  } catch (e) {
    res.locals.csrfToken = '';
  }
  next();
});

function csrfGuard(req, res, next) {
  doubleCsrfProtection(req, res, (err) => {
    if (err) return res.status(403).render('login_error_fallback') || res.status(403).send('Invalid or expired security token. Please refresh and try again.');
    next();
  });
}

/* ============================================================
 * SECTION: AUTH HELPERS
 * ============================================================ */
async function hashPassword(pw) { return bcrypt.hash(pw, 12); }
async function verifyPassword(pw, hash) { return bcrypt.compare(pw, hash); }

function currentUser(req) { return req.session && req.session.user ? req.session.user : null; }

function requireAuth(req, res, next) {
  if (!currentUser(req)) {
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Authentication required.' });
    return res.redirect('/login');
  }
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    const u = currentUser(req);
    if (!u || !roles.includes(u.role)) {
      if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'Forbidden.' });
      return res.status(403).send('403 Forbidden: you do not have access to this resource.');
    }
    next();
  };
}

async function auditLog(req, action, targetType, targetId, metadata = {}) {
  try {
    const u = currentUser(req);
    await AuditLog.create({
      actor_id: u ? u.id : null,
      actor_role: u ? u.role : 'anonymous',
      action,
      target_type: targetType,
      target_id: String(targetId || ''),
      ip: req.ip,
      user_agent: req.headers['user-agent'] || '',
      metadata,
    });
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('[BMA] audit log failure:', e.message);
  }
}

async function notify(ownerId, ownerRole, type, title, message) {
  await Notification.create({ owner_id: ownerId, owner_role: ownerRole, type, title, message });
}

/* ============================================================
 * SECTION: FINANCIAL HELPERS (integer-minor-unit arithmetic)
 * ============================================================ */
function toMinor(amount) { return Math.round(Number(amount) * 100); } // 2 decimal places, integer safe
function fromMinor(minor) { return minor / 100; }

async function getSystemSettings() {
  let s = await SystemSetting.findOne({ singleton: 'main' });
  if (!s) s = await SystemSetting.create({ singleton: 'main' });
  return s;
}

function bmcFromBdtMinor(bdtMinor, rate) {
  // amount_bmc (minor) = bdt_minor / rate, rounded to nearest minor unit
  return Math.round(bdtMinor / rate);
}
function bdtFromBmcMinor(bmcMinor, rate) {
  return Math.round(bmcMinor * rate);
}

function newRef(prefix) { return `${prefix}-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`; }

/* ============================================================
 * SECTION: LEDGER (append-only, hash-chained double-entry)
 * ============================================================ */
const GENESIS_HASH = '0'.repeat(64);

function computeEntryHash(entry, previousHash) {
  const payload = JSON.stringify({
    transaction_id: entry.transaction_id,
    wallet_id: String(entry.wallet_id),
    entry_type: entry.entry_type,
    direction: entry.direction,
    amount_bmc_minor: entry.amount_bmc_minor,
    amount_bdt_minor: entry.amount_bdt_minor,
    rate_bdt: entry.rate_bdt,
    balance_before: entry.balance_before,
    balance_after: entry.balance_after,
    reference: entry.reference,
    previous_hash: previousHash,
  });
  return crypto.createHash('sha256').update(payload).digest('hex');
}

/**
 * Writes a single ledger entry for a wallet inside an active mongoose session,
 * atomically updating the wallet's authoritative balance cache.
 */
async function writeLedgerEntry(session, { walletId, transactionId, entryType, direction, amountBmcMinor, amountBdtMinor, rateBdt, reference }) {
  const wallet = await Wallet.findById(walletId).session(session);
  if (!wallet) throw new Error('Wallet not found for ledger entry.');

  const balanceBefore = wallet.balance_minor_cache;
  let balanceAfter;
  if (direction === 'debit') {
    balanceAfter = balanceBefore - amountBmcMinor;
    if (balanceAfter < 0) throw new Error('INSUFFICIENT_FUNDS');
  } else {
    balanceAfter = balanceBefore + amountBmcMinor;
  }

  const lastEntry = await LedgerEntry.findOne({ wallet_id: walletId }).sort({ created_at: -1, _id: -1 }).session(session);
  const previousHash = lastEntry ? lastEntry.current_hash : GENESIS_HASH;

  const draft = {
    transaction_id: transactionId,
    wallet_id: walletId,
    entry_type: entryType,
    direction,
    amount_bmc_minor: amountBmcMinor,
    amount_bdt_minor: amountBdtMinor,
    rate_bdt: rateBdt,
    balance_before: balanceBefore,
    balance_after: balanceAfter,
    reference: reference || '',
  };
  const currentHash = computeEntryHash(draft, previousHash);

  await LedgerEntry.create([{
    transaction_id: transactionId,
    wallet_id: walletId,
    entry_type: entryType,
    direction,
    amount_bmc: dec(fromMinor(amountBmcMinor)),
    amount_bdt: dec(fromMinor(amountBdtMinor)),
    rate_bdt: rateBdt,
    balance_before: balanceBefore,
    balance_after: balanceAfter,
    previous_hash: previousHash,
    current_hash: currentHash,
    reference: reference || '',
  }], { session });

  wallet.balance_minor_cache = balanceAfter;
  await wallet.save({ session });

  return balanceAfter;
}

/**
 * Performs a balanced double-entry posting: debit one wallet, credit another,
 * for the same BMC amount, within the given session.
 */
async function postDoubleEntry(session, { transactionId, debitWalletId, creditWalletId, amountBmcMinor, rateBdt, entryType, reference }) {
  const amountBdtMinor = bdtFromBmcMinor(amountBmcMinor, rateBdt);
  await writeLedgerEntry(session, { walletId: debitWalletId, transactionId, entryType, direction: 'debit', amountBmcMinor, amountBdtMinor, rateBdt, reference });
  await writeLedgerEntry(session, { walletId: creditWalletId, transactionId, entryType, direction: 'credit', amountBmcMinor, amountBdtMinor, rateBdt, reference });
}

async function verifyLedgerIntegrity() {
  const wallets = await Wallet.find({});
  for (const wallet of wallets) {
    const entries = await LedgerEntry.find({ wallet_id: wallet._id }).sort({ created_at: 1, _id: 1 });
    let expectedPrev = GENESIS_HASH;
    let runningBalance = 0;
    for (const e of entries) {
      const draft = {
        transaction_id: e.transaction_id,
        wallet_id: e.wallet_id,
        entry_type: e.entry_type,
        direction: e.direction,
        amount_bmc_minor: toMinor(decToNum(e.amount_bmc)),
        amount_bdt_minor: toMinor(decToNum(e.amount_bdt)),
        rate_bdt: e.rate_bdt,
        balance_before: e.balance_before,
        balance_after: e.balance_after,
        reference: e.reference,
      };
      const recomputedHash = computeEntryHash(draft, expectedPrev);
      if (recomputedHash !== e.current_hash || e.previous_hash !== expectedPrev) {
        return { valid: false, failedAt: String(e._id) };
      }
      runningBalance = e.balance_after;
      expectedPrev = e.current_hash;
    }
    if (runningBalance !== wallet.balance_minor_cache) {
      return { valid: false, failedAt: `wallet:${wallet._id} balance mismatch` };
    }
  }
  return { valid: true, failedAt: null };
}

/* ============================================================
 * SECTION: WALLET
 * ============================================================ */
async function getOrCreateWallet(ownerId, ownerType, session = null) {
  const query = Wallet.findOne({ owner_id: ownerId, owner_type: ownerType });
  if (session) query.session(session);
  let wallet = await query;
  if (!wallet) {
    const created = await Wallet.create([{ owner_id: ownerId, owner_type: ownerType }], session ? { session } : {});
    wallet = Array.isArray(created) ? created[0] : created;
  }
  return wallet;
}

/* ============================================================
 * SECTION: IDEMPOTENCY
 * ============================================================ */
async function withIdempotency(key, scope, requestPayload, fn) {
  const requestHash = crypto.createHash('sha256').update(JSON.stringify(requestPayload)).digest('hex');
  const existing = await IdempotencyKey.findOne({ key });
  if (existing) {
    if (existing.request_hash !== requestHash) {
      const err = new Error('Idempotency key reused with different parameters.');
      err.code = 'IDEMPOTENCY_CONFLICT';
      throw err;
    }
    return existing.response_snapshot;
  }
  const record = await IdempotencyKey.create({ key, scope, request_hash: requestHash, status: 'pending' });
  try {
    const result = await fn();
    record.status = 'completed';
    record.response_snapshot = result;
    await record.save();
    return result;
  } catch (e) {
    record.status = 'failed';
    await record.save();
    throw e;
  }
}

/* ============================================================
 * SECTION: PAYMENT PROVIDER ABSTRACTION
 * ============================================================ */
const paymentProviderDrivers = {
  test: {
    async createPayment({ amountBdt, reference }) {
      return { providerPaymentId: `TEST-PAY-${reference}`, redirectUrl: `${APP_URL}/api/webhooks/payment?simulate=1&ref=${reference}` };
    },
    async verifyWebhookSignature(rawBody, signatureHeader) {
      return true; // test driver has no real signature scheme
    },
    async getPaymentStatus({ providerPaymentId }) {
      return { status: 'Completed', providerPaymentId };
    },
    async refundPayment({ providerPaymentId, amountBdt }) {
      return { status: 'Completed', providerRefundId: `TEST-REFUND-${providerPaymentId}` };
    },
  },
  generic: {
    async createPayment() {
      throw new Error('No live payment provider integration is connected. Configure PAYMENT_PROVIDER credentials with your licensed payment partner before accepting real payments.');
    },
    async verifyWebhookSignature(rawBody, signatureHeader) {
      if (!process.env.PAYMENT_WEBHOOK_SECRET) return false;
      const expected = crypto.createHmac('sha256', process.env.PAYMENT_WEBHOOK_SECRET).update(rawBody).digest('hex');
      return signatureHeader && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(signatureHeader)));
    },
    async getPaymentStatus() {
      throw new Error('No live payment provider integration is connected.');
    },
    async refundPayment() {
      throw new Error('No live payment provider integration is connected.');
    },
  },
};

function activePaymentDriver() {
  if (!IS_PROD && (!process.env.PAYMENT_PROVIDER || process.env.PAYMENT_PROVIDER === 'test')) {
    return paymentProviderDrivers.test;
  }
  if (IS_PROD && (!process.env.PAYMENT_API_KEY || !process.env.PAYMENT_API_SECRET)) {
    return null; // production without real credentials must not process payments
  }
  return paymentProviderDrivers.generic;
}

const settlementProviderDrivers = {
  test: {
    async createSettlement({ amountBdt, reference }) {
      return { providerSettlementId: `TEST-STL-${reference}`, status: 'Processing' };
    },
    async getSettlementStatus() { return { status: 'Completed' }; },
  },
  generic: {
    async createSettlement() {
      throw new Error('No live settlement provider integration is connected. Configure SETTLEMENT_PROVIDER credentials before running real settlement.');
    },
    async getSettlementStatus() {
      throw new Error('No live settlement provider integration is connected.');
    },
  },
};
function activeSettlementDriver() {
  if (!IS_PROD && (!process.env.SETTLEMENT_PROVIDER || process.env.SETTLEMENT_PROVIDER === 'test')) {
    return settlementProviderDrivers.test;
  }
  if (IS_PROD && (!process.env.SETTLEMENT_API_KEY || !process.env.SETTLEMENT_API_SECRET)) {
    return null;
  }
  return settlementProviderDrivers.generic;
}

/* ============================================================
 * SECTION: RISK ENGINE
 * ============================================================ */
async function riskCheck(subjectType, subjectId, checkType, context) {
  const settings = await getSystemSettings();
  let flagged = false;
  let details = context || {};

  if (checkType === 'large_transaction' && context.amountBdt > settings.risk_threshold) {
    flagged = true;
  }
  if (checkType === 'velocity') {
    const since = new Date(Date.now() - 60 * 60 * 1000);
    const count = await Transaction.countDocuments({ user_id: subjectId, created_at: { $gte: since } });
    if (count > 10) flagged = true;
    details.recentCount = count;
  }
  if (checkType === 'failed_login') {
    if (context.failedAttempts >= 5) flagged = true;
  }

  if (flagged) {
    await RiskAlert.create({
      ref: newRef('RISK'),
      type: checkType,
      subject_type: subjectType,
      subject_id: String(subjectId),
      severity: 'Flagged',
      status: 'Open',
      details,
    });
  }
  return { flagged };
}

/* ============================================================
 * SECTION: RECONCILIATION
 * ============================================================ */
async function runReconciliation() {
  const wallets = await Wallet.find({});
  const ledgerTotalMinor = wallets.reduce((sum, w) => sum + w.balance_minor_cache, 0);
  // Provider total is a placeholder computed from completed deposits minus completed settlements,
  // representing funds that should exist with the payment/settlement partners pending an authorized bank report.
  const deposits = await Deposit.find({ status: 'Completed' });
  const settlements = await Settlement.find({ status: 'Completed' });
  const depositTotalMinor = deposits.reduce((s, d) => s + toMinor(decToNum(d.amount_bmc)), 0);
  const settlementTotalMinor = settlements.reduce((s, st) => s + toMinor(decToNum(st.amount_bmc)), 0);
  const providerTotalMinor = depositTotalMinor - settlementTotalMinor;
  const variance = fromMinor(ledgerTotalMinor - providerTotalMinor);

  const record = await Reconciliation.create({
    ref: newRef('RECON'),
    ledger_total: fromMinor(ledgerTotalMinor),
    provider_total: fromMinor(providerTotalMinor),
    variance,
    status: Math.abs(variance) < 0.01 ? 'Matched' : 'Mismatch',
  });
  if (record.status === 'Mismatch') {
    await RiskAlert.create({
      ref: newRef('RISK'),
      type: 'reconciliation_mismatch',
      subject_type: 'system',
      subject_id: record.ref,
      severity: 'Under Review',
      status: 'Open',
      details: { variance },
    });
  }
  return record;
}

/* ============================================================
 * SECTION: BOOTSTRAP INITIAL ADMIN
 * ============================================================ */
async function ensureInitialAdmin() {
  const existingAdmin = await User.findOne({ role: 'admin' });
  if (existingAdmin) return;
  if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) return;
  const hash = await hashPassword(process.env.ADMIN_PASSWORD);
  await User.create({
    full_name: 'System Administrator',
    email: process.env.ADMIN_EMAIL.toLowerCase(),
    phone: '0000000000',
    password_hash: hash,
    role: 'admin',
    status: 'active',
  });
  // eslint-disable-next-line no-console
  console.log('[BMA] Initial admin account created.');
}

/* ============================================================
 * SECTION: VIEW HELPERS
 * ============================================================ */
function fmtDate(d) { return d ? new Date(d).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : ''; }

async function unreadNotificationCount(ownerId) {
  return Notification.countDocuments({ owner_id: ownerId, read: false });
}

/* ============================================================
 * SECTION: AUTH ROUTES
 * ============================================================ */
app.get('/', (req, res) => res.redirect(currentUser(req) ? '/app/dashboard' : '/login'));

app.get('/login', async (req, res) => {
  if (currentUser(req)) return res.redirect('/app/dashboard');
  const settings = await getSystemSettings();
  res.render('login', { error: null, notice: null, coinRate: settings.coin_rate_bdt, csrfToken: res.locals.csrfToken });
});

app.post('/login', authLimiter, csrfGuard,
  body('identifier').trim().notEmpty(),
  body('password').notEmpty(),
  async (req, res) => {
    const errors = validationResult(req);
    const settings = await getSystemSettings();
    if (!errors.isEmpty()) {
      return res.status(400).render('login', { error: 'Please provide valid credentials.', notice: null, coinRate: settings.coin_rate_bdt, csrfToken: res.locals.csrfToken });
    }
    const { identifier, password } = req.body;
    const userDoc = await User.findOne({ $or: [{ email: identifier.toLowerCase() }, { phone: identifier }] });
    const genericError = 'Invalid email/phone or password.';

    if (!userDoc) return res.status(401).render('login', { error: genericError, notice: null, coinRate: settings.coin_rate_bdt, csrfToken: res.locals.csrfToken });

    if (userDoc.lock_until && userDoc.lock_until > new Date()) {
      return res.status(423).render('login', { error: 'Account temporarily locked due to repeated failed attempts. Try again later.', notice: null, coinRate: settings.coin_rate_bdt, csrfToken: res.locals.csrfToken });
    }
    if (['suspended', 'frozen', 'deleted'].includes(userDoc.status)) {
      return res.status(403).render('login', { error: 'This account is not active. Contact support.', notice: null, coinRate: settings.coin_rate_bdt, csrfToken: res.locals.csrfToken });
    }

    const ok = await verifyPassword(password, userDoc.password_hash);
    if (!ok) {
      userDoc.failed_login_attempts += 1;
      if (userDoc.failed_login_attempts >= 5) {
        userDoc.lock_until = new Date(Date.now() + 15 * 60 * 1000);
        await riskCheck('user', userDoc._id, 'failed_login', { failedAttempts: userDoc.failed_login_attempts });
      }
      await userDoc.save();
      return res.status(401).render('login', { error: genericError, notice: null, coinRate: settings.coin_rate_bdt, csrfToken: res.locals.csrfToken });
    }

    userDoc.failed_login_attempts = 0;
    userDoc.lock_until = null;
    userDoc.last_login = new Date();
    await userDoc.save();

    req.session.regenerate(async (err) => {
      if (err) return res.status(500).render('login', { error: 'Something went wrong. Please try again.', notice: null, coinRate: settings.coin_rate_bdt, csrfToken: res.locals.csrfToken });
      req.session.user = { id: String(userDoc._id), role: userDoc.role, full_name: userDoc.full_name, email: userDoc.email, phone: userDoc.phone };
      await DeviceSession.create({
        user_id: userDoc._id,
        session_id: req.sessionID,
        device: req.headers['user-agent'] || 'Unknown device',
        ip: req.ip,
        user_agent: req.headers['user-agent'] || '',
      });
      await auditLog(req, 'login', 'User', userDoc._id);
      await notify(userDoc._id, userDoc.role, 'Security', 'New Login', `A new sign-in was detected from ${req.ip}.`);
      res.redirect('/app/dashboard');
    });
  });

app.post('/register', authLimiter, csrfGuard,
  body('full_name').trim().isLength({ min: 2, max: 120 }),
  body('email').isEmail().normalizeEmail(),
  body('phone').trim().isLength({ min: 6, max: 32 }),
  body('password').isLength({ min: 8, max: 128 }),
  body('role').isIn(['user', 'merchant']),
  async (req, res) => {
    const settings = await getSystemSettings();
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('login', { error: 'Please check your registration details.', notice: null, coinRate: settings.coin_rate_bdt, csrfToken: res.locals.csrfToken });
    }
    if (!settings.registration_enabled) {
      return res.status(403).render('login', { error: 'Registration is currently disabled.', notice: null, coinRate: settings.coin_rate_bdt, csrfToken: res.locals.csrfToken });
    }
    if (req.body.role === 'merchant' && !settings.merchant_registration_enabled) {
      return res.status(403).render('login', { error: 'Merchant registration is currently disabled.', notice: null, coinRate: settings.coin_rate_bdt, csrfToken: res.locals.csrfToken });
    }
    const { full_name, email, phone, password, role } = req.body;
    const exists = await User.findOne({ $or: [{ email: email.toLowerCase() }, { phone }] });
    if (exists) {
      return res.status(409).render('login', { error: 'An account with this email or phone already exists.', notice: null, coinRate: settings.coin_rate_bdt, csrfToken: res.locals.csrfToken });
    }
    const password_hash = await hashPassword(password);
    const userDoc = await User.create({ full_name, email: email.toLowerCase(), phone, password_hash, role, status: 'active' });
    await getOrCreateWallet(userDoc._id, 'user');

    if (role === 'merchant') {
      const merchant = await Merchant.create({
        user_id: userDoc._id,
        merchant_ref: newRef('MER'),
        business_name: full_name,
        owner_name: full_name,
        phone, email: email.toLowerCase(),
        status: 'Pending',
      });
      await getOrCreateWallet(merchant._id, 'merchant_pending');
      await getOrCreateWallet(merchant._id, 'merchant_available');
      await KYB.create({ merchant_id: merchant._id, status: 'Pending' });
    } else {
      await KYC.create({ user_id: userDoc._id, status: 'Not Started' });
    }
    await auditLog(req, 'register', 'User', userDoc._id, { role });
    res.render('login', { error: null, notice: 'Account created successfully. Please sign in.', coinRate: settings.coin_rate_bdt, csrfToken: res.locals.csrfToken });
  });

app.post('/forgot-password', authLimiter, csrfGuard, body('email').isEmail().normalizeEmail(), async (req, res) => {
  const settings = await getSystemSettings();
  const genericNotice = 'If an account matches this email, reset instructions have been sent.';
  const userDoc = await User.findOne({ email: req.body.email });
  if (userDoc) {
    const token = crypto.randomBytes(32).toString('hex');
    userDoc.reset_token_hash = crypto.createHash('sha256').update(token).digest('hex');
    userDoc.reset_token_expires = new Date(Date.now() + 30 * 60 * 1000);
    await userDoc.save();
    await notify(userDoc._id, userDoc.role, 'Security', 'Password Reset Requested', 'A password reset was requested for your account. If this was not you, contact support.');
    // In production this token would be emailed via a transactional email provider, never returned in the response.
  }
  res.render('login', { error: null, notice: genericNotice, coinRate: settings.coin_rate_bdt, csrfToken: res.locals.csrfToken });
});

app.post('/logout', requireAuth, csrfGuard, async (req, res) => {
  const u = currentUser(req);
  await auditLog(req, 'logout', 'User', u.id);
  await DeviceSession.updateOne({ session_id: req.sessionID }, { revoked: true });
  req.session.destroy(() => {
    res.clearCookie('bma.sid');
    res.redirect('/login');
  });
});

/* ============================================================
 * SECTION: ROLE-SCOPED DATA LOADERS FOR /app/:page
 * ============================================================ */
const PAGE_ACCESS = {
  dashboard: ['user', 'merchant', 'admin'],
  wallet: ['user', 'merchant'],
  'add-money': ['user'],
  'scan-pay': ['user'],
  transactions: ['user', 'merchant', 'admin'],
  refunds: ['user', 'merchant', 'admin'],
  disputes: ['user', 'merchant', 'admin'],
  orders: ['merchant'],
  qr: ['merchant'],
  settlement: ['merchant'],
  'auto-settlement': ['merchant'],
  reports: ['merchant'],
  kyc: ['user', 'admin'],
  kyb: ['merchant', 'admin'],
  notifications: ['user', 'merchant', 'admin'],
  profile: ['user', 'merchant', 'admin'],
  security: ['user', 'merchant', 'admin'],
  users: ['admin'],
  merchants: ['admin'],
  deposits: ['admin'],
  settlements: ['admin'],
  reserve: ['admin'],
  reconciliation: ['admin'],
  'risk-alerts': ['admin'],
  'audit-logs': ['admin'],
  'system-settings': ['admin'],
  'payment-providers': ['admin'],
  'settlement-providers': ['admin'],
};

async function getMerchantForUser(userId) { return Merchant.findOne({ user_id: userId }); }

app.get('/app', requireAuth, (req, res) => res.redirect('/app/dashboard'));

app.get('/app/:page', requireAuth, async (req, res, next) => {
  try {
    const u = currentUser(req);
    const page = req.params.page;
    const allowed = PAGE_ACCESS[page];
    if (!allowed || !allowed.includes(u.role)) return res.status(403).send('403 Forbidden');

    const settings = await getSystemSettings();
    const unreadCount = await unreadNotificationCount(u.id);
    let data = {};
    let merchantDoc = null;
    if (u.role === 'merchant') merchantDoc = await getMerchantForUser(u.id);

    if (page === 'dashboard' && u.role === 'user') {
      const wallet = await getOrCreateWallet(u.id, 'user');
      const since = new Date(); since.setDate(1);
      const monthTx = await Transaction.find({ user_id: u.id, type: 'Payment', status: 'Completed', created_at: { $gte: since } });
      const recentTxDocs = await Transaction.find({ user_id: u.id }).sort({ created_at: -1 }).limit(8);
      const pendingRefunds = await Refund.countDocuments({ user_id: u.id, status: { $in: ['Requested', 'Processing'] } });
      const recentTx = await Promise.all(recentTxDocs.map(async (t) => {
        let merchant_name = null;
        if (t.merchant_id) { const m = await Merchant.findById(t.merchant_id); merchant_name = m ? m.business_name : null; }
        return { merchant_name, tx_id: t.tx_id, amount_bmc: decToNum(t.amount_bmc), amount_bdt: decToNum(t.amount_bdt), status: t.status, date: fmtDate(t.created_at) };
      }));
      data = {
        wallet: { balance_bmc: fromMinor(wallet.balance_minor_cache), balance_bdt: fromMinor(wallet.balance_minor_cache) * settings.coin_rate_bdt },
        monthSpentBmc: monthTx.reduce((s, t) => s + decToNum(t.amount_bmc), 0),
        monthSpentBdt: monthTx.reduce((s, t) => s + decToNum(t.amount_bdt), 0),
        pendingRefunds, recentTx,
      };
    }

    if (page === 'wallet') {
      let wallet, pendingBalance = 0, availableBalance = 0, ledgerDocs;
      if (u.role === 'user') {
        wallet = await getOrCreateWallet(u.id, 'user');
        ledgerDocs = await LedgerEntry.find({ wallet_id: wallet._id }).sort({ created_at: -1 }).limit(50);
      } else {
        const pendingWallet = await getOrCreateWallet(merchantDoc._id, 'merchant_pending');
        const availWallet = await getOrCreateWallet(merchantDoc._id, 'merchant_available');
        pendingBalance = fromMinor(pendingWallet.balance_minor_cache);
        availableBalance = fromMinor(availWallet.balance_minor_cache);
        wallet = { balance_minor_cache: pendingWallet.balance_minor_cache + availWallet.balance_minor_cache };
        ledgerDocs = await LedgerEntry.find({ wallet_id: { $in: [pendingWallet._id, availWallet._id] } }).sort({ created_at: -1 }).limit(50);
      }
      data = {
        wallet: { balance_bmc: fromMinor(wallet.balance_minor_cache), balance_bdt: fromMinor(wallet.balance_minor_cache) * settings.coin_rate_bdt },
        pendingBalance, availableBalance,
        ledger: ledgerDocs.map((l) => ({ date: fmtDate(l.created_at), entry_type: l.entry_type, direction: l.direction, amount_bmc: decToNum(l.amount_bmc), amount_bdt: decToNum(l.amount_bdt), balance_after: fromMinor(l.balance_after), reference: l.reference })),
      };
    }

    if (page === 'add-money') {
      const deposits = await Deposit.find({ user_id: u.id }).sort({ created_at: -1 }).limit(20);
      data = { coinRate: settings.coin_rate_bdt, deposits: deposits.map((d) => ({ reference: d.reference, amount_bdt: decToNum(d.amount_bdt), status: d.status, date: fmtDate(d.created_at) })) };
    }

    if (page === 'scan-pay') {
      let merchant = null;
      if (req.query.ref) {
        const m = await Merchant.findOne({ merchant_ref: req.query.ref });
        if (m) merchant = { business_name: m.business_name, ref: m.merchant_ref, status: m.status };
      }
      data = { coinRate: settings.coin_rate_bdt, merchant };
    }

    if (page === 'qr' && u.role === 'merchant') {
      const qrPayload = JSON.stringify({ ref: merchantDoc.merchant_ref });
      const qrDataUrl = await QRCode.toDataURL(qrPayload, { margin: 1, scale: 6 });
      const recentPaymentsDocs = await Payment.find({ merchant_id: merchantDoc._id }).sort({ created_at: -1 }).limit(10);
      const recentPayments = await Promise.all(recentPaymentsDocs.map(async (p) => {
        const usr = await User.findById(p.user_id);
        return { user_ref: usr ? usr.full_name : 'Unknown', amount_bmc: decToNum(p.amount_bmc), amount_bdt: decToNum(p.amount_bdt), status: p.status, date: fmtDate(p.created_at) };
      }));
      data = { qrDataUrl, merchantRef: merchantDoc.merchant_ref, merchantStatus: merchantDoc.status, recentPayments };
    }

    if (page === 'dashboard' && u.role === 'merchant') {
      const pendingWallet = await getOrCreateWallet(merchantDoc._id, 'merchant_pending');
      const availWallet = await getOrCreateWallet(merchantDoc._id, 'merchant_available');
      const startToday = new Date(); startToday.setHours(0, 0, 0, 0);
      const startMonth = new Date(); startMonth.setDate(1); startMonth.setHours(0, 0, 0, 0);
      const todayPayments = await Payment.find({ merchant_id: merchantDoc._id, status: 'Completed', created_at: { $gte: startToday } });
      const monthPayments = await Payment.find({ merchant_id: merchantDoc._id, status: 'Completed', created_at: { $gte: startMonth } });
      const pendingSettlement = await Settlement.find({ merchant_id: merchantDoc._id, status: { $in: ['Pending', 'Processing'] } });
      const completedSettlement = await Settlement.find({ merchant_id: merchantDoc._id, status: 'Completed' });
      const salesLabels = []; const salesSeries = [];
      for (let i = 6; i >= 0; i--) {
        const day = new Date(); day.setDate(day.getDate() - i); day.setHours(0, 0, 0, 0);
        const nextDay = new Date(day); nextDay.setDate(day.getDate() + 1);
        const dayPayments = await Payment.find({ merchant_id: merchantDoc._id, status: 'Completed', created_at: { $gte: day, $lt: nextDay } });
        salesLabels.push(day.toLocaleDateString('en-US', { weekday: 'short' }));
        salesSeries.push(dayPayments.reduce((s, p) => s + decToNum(p.amount_bmc), 0));
      }
      data = {
        availableBalance: fromMinor(availWallet.balance_minor_cache),
        pendingBalance: fromMinor(pendingWallet.balance_minor_cache),
        todaySales: todayPayments.reduce((s, p) => s + decToNum(p.amount_bmc), 0),
        monthSales: monthPayments.reduce((s, p) => s + decToNum(p.amount_bmc), 0),
        pendingSettlement: pendingSettlement.reduce((s, x) => s + decToNum(x.amount_bmc), 0),
        completedSettlement: completedSettlement.reduce((s, x) => s + decToNum(x.amount_bmc), 0),
        coinRate: settings.coin_rate_bdt, salesLabels, salesSeries,
      };
    }

    if (page === 'dashboard' && u.role === 'admin') {
      const usersCount = await User.countDocuments({ role: 'user' });
      const merchantsCount = await Merchant.countDocuments({});
      const wallets = await Wallet.find({});
      const outstandingBmc = fromMinor(wallets.reduce((s, w) => s + w.balance_minor_cache, 0));
      const openDisputes = await Dispute.countDocuments({ status: { $nin: ['Resolved', 'Rejected'] } });
      const riskAlerts = await RiskAlert.countDocuments({ status: { $ne: 'Resolved' } });
      const pendingKyc = await KYC.countDocuments({ status: { $in: ['Pending', 'Under Review'] } });
      const pendingKyb = await KYB.countDocuments({ status: { $in: ['Pending', 'Under Review'] } });
      const volLabels = []; const volSeries = [];
      for (let i = 6; i >= 0; i--) {
        const day = new Date(); day.setDate(day.getDate() - i); day.setHours(0, 0, 0, 0);
        const nextDay = new Date(day); nextDay.setDate(day.getDate() + 1);
        const dayTx = await Transaction.find({ status: 'Completed', created_at: { $gte: day, $lt: nextDay } });
        volLabels.push(day.toLocaleDateString('en-US', { weekday: 'short' }));
        volSeries.push(dayTx.reduce((s, t) => s + decToNum(t.amount_bmc), 0));
      }
      data = { usersCount, merchantsCount, outstandingBmc, expectedReserveBdt: outstandingBmc * settings.coin_rate_bdt, openDisputes, riskAlerts, pendingKyc, pendingKyb, volLabels, volSeries };
    }

    if (page === 'transactions') {
      const filter = {};
      if (u.role === 'user') filter.user_id = u.id;
      if (u.role === 'merchant') filter.merchant_id = merchantDoc._id;
      if (req.query.status) filter.status = req.query.status;
      if (req.query.type) filter.type = req.query.type;
      if (req.query.date) {
        const d = new Date(req.query.date); const next = new Date(d); next.setDate(d.getDate() + 1);
        filter.created_at = { $gte: d, $lt: next };
      }
      const txDocs = await Transaction.find(filter).sort({ created_at: -1 }).limit(100);
      const transactions = await Promise.all(txDocs.map(async (t) => {
        let counterparty = '—';
        if (u.role === 'user' && t.merchant_id) { const m = await Merchant.findById(t.merchant_id); counterparty = m ? m.business_name : '—'; }
        if (u.role !== 'user' && t.user_id) { const usr = await User.findById(t.user_id); counterparty = usr ? usr.full_name : '—'; }
        return { tx_id: t.tx_id, type: t.type, counterparty, amount_bmc: decToNum(t.amount_bmc), amount_bdt: decToNum(t.amount_bdt), rate_bdt: t.rate_bdt, status: t.status, date: fmtDate(t.created_at) };
      }));
      data = { transactions };
    }

    if (page === 'transaction-detail') {
      // handled by dedicated route below
    }

    if (page === 'refunds') {
      const filter = {};
      if (u.role === 'user') filter.user_id = u.id;
      if (u.role === 'merchant') filter.merchant_id = merchantDoc._id;
      const refundDocs = await Refund.find(filter).sort({ created_at: -1 }).limit(100);
      data = { refunds: refundDocs.map((r) => ({ ref: r.ref, original_tx: r.original_tx_id, amount_bmc: decToNum(r.amount_bmc), status: r.status, date: fmtDate(r.created_at) })) };
    }

    if (page === 'disputes') {
      const filter = {};
      if (u.role === 'user') filter.user_id = u.id;
      if (u.role === 'merchant') filter.merchant_id = merchantDoc._id;
      const disputeDocs = await Dispute.find(filter).sort({ created_at: -1 }).limit(100);
      data = { disputes: disputeDocs.map((d) => ({ ref: d.ref, tx_id: d.tx_id, status: d.status, date: fmtDate(d.created_at) })) };
    }

    if (page === 'orders') {
      const orderDocs = await Order.find({ merchant_id: merchantDoc._id }).sort({ created_at: -1 }).limit(100);
      data = { orders: orderDocs.map((o) => ({ order_id: o.order_id, total_bmc: decToNum(o.total_bmc), total_bdt: decToNum(o.total_bdt), payment_status: o.payment_status, fulfillment_status: o.fulfillment_status, date: fmtDate(o.created_at) })) };
    }

    if (page === 'settlement') {
      const availWallet = await getOrCreateWallet(merchantDoc._id, 'merchant_available');
      const settlementDocs = await Settlement.find({ merchant_id: merchantDoc._id }).sort({ created_at: -1 }).limit(50);
      data = {
        availableBalance: fromMinor(availWallet.balance_minor_cache),
        minSettlement: merchantDoc.auto_settlement.min_amount,
        autoEnabled: merchantDoc.auto_settlement.enabled,
        settlements: settlementDocs.map((s) => ({ ref: s.ref, amount_bmc: decToNum(s.amount_bmc), amount_bdt: decToNum(s.amount_bdt), status: s.status, date: fmtDate(s.created_at) })),
      };
    }

    if (page === 'auto-settlement') {
      data = { settings: { enabled: merchantDoc.auto_settlement.enabled, frequency: merchantDoc.auto_settlement.frequency, min_amount: merchantDoc.auto_settlement.min_amount, account_masked: merchantDoc.settlement_account_masked } };
    }

    if (page === 'reports') {
      const labels = []; const series = [];
      for (let i = 5; i >= 0; i--) {
        const day = new Date(); day.setMonth(day.getMonth() - i); day.setDate(1); day.setHours(0, 0, 0, 0);
        const next = new Date(day); next.setMonth(day.getMonth() + 1);
        const pays = await Payment.find({ merchant_id: merchantDoc._id, status: 'Completed', created_at: { $gte: day, $lt: next } });
        labels.push(day.toLocaleDateString('en-US', { month: 'short' }));
        series.push(pays.reduce((s, p) => s + decToNum(p.amount_bmc), 0));
      }
      data = { labels, series };
    }

    if (page === 'kyc') {
      if (u.role === 'user') {
        const kyc = await KYC.findOne({ user_id: u.id }) || { status: 'Not Started' };
        data = { kyc };
      } else {
        const kycDocs = await KYC.find({ status: { $in: ['Pending', 'Under Review'] } }).sort({ submitted_at: -1 }).limit(100);
        data = { kycList: kycDocs.map((k) => ({ id: k._id, full_name: k.full_name, identification_type: k.identification_type, status: k.status, date: fmtDate(k.submitted_at) })) };
      }
    }

    if (page === 'kyb') {
      if (u.role === 'merchant') {
        const kyb = await KYB.findOne({ merchant_id: merchantDoc._id }) || { status: 'Pending' };
        data = { kyb };
      } else {
        const kybDocs = await KYB.find({ status: { $in: ['Pending', 'Under Review'] } }).sort({ submitted_at: -1 }).limit(100);
        data = { kybList: kybDocs.map((k) => ({ id: k._id, business_name: k.business_name, owner_name: k.owner_name, status: k.status, date: fmtDate(k.submitted_at) })) };
      }
    }

    if (page === 'notifications') {
      const notifDocs = await Notification.find({ owner_id: u.id }).sort({ created_at: -1 }).limit(50);
      data = { notifications: notifDocs.map((n) => ({ id: n._id, title: n.title, message: n.message, read: n.read, date: fmtDate(n.created_at) })) };
      await Notification.updateMany({ owner_id: u.id, read: false }, { $set: { read: true } });
    }

    if (page === 'security') {
      const sessions = await DeviceSession.find({ user_id: u.id, revoked: false }).sort({ last_seen: -1 }).limit(20);
      data = { sessions: sessions.map((s) => ({ id: s._id, device: s.device, ip: s.ip, last_seen: fmtDate(s.last_seen) })) };
    }

    if (page === 'users' && u.role === 'admin') {
      const users = await User.find({ role: 'user' }).sort({ created_at: -1 }).limit(150);
      data = { users: users.map((x) => ({ id: x._id, full_name: x.full_name, email: x.email, status: x.status, date: fmtDate(x.created_at) })) };
    }

    if (page === 'merchants' && u.role === 'admin') {
      const merchants = await Merchant.find({}).sort({ created_at: -1 }).limit(150);
      data = { merchants: merchants.map((m) => ({ id: m._id, business_name: m.business_name, owner_name: m.owner_name, status: m.status, date: fmtDate(m.created_at) })) };
    }

    if (page === 'deposits' && u.role === 'admin') {
      const depositDocs = await Deposit.find({}).sort({ created_at: -1 }).limit(150);
      data = { deposits: await Promise.all(depositDocs.map(async (d) => { const usr = await User.findById(d.user_id); return { reference: d.reference, user_name: usr ? usr.full_name : '—', amount_bdt: decToNum(d.amount_bdt), status: d.status, date: fmtDate(d.created_at) }; })) };
    }

    if (page === 'settlements' && u.role === 'admin') {
      const settlementDocs = await Settlement.find({}).sort({ created_at: -1 }).limit(150);
      data = { settlements: await Promise.all(settlementDocs.map(async (s) => { const m = await Merchant.findById(s.merchant_id); return { ref: s.ref, merchant_name: m ? m.business_name : '—', amount_bmc: decToNum(s.amount_bmc), amount_bdt: decToNum(s.amount_bdt), status: s.status, date: fmtDate(s.created_at) }; })) };
    }

    if (page === 'reserve' && u.role === 'admin') {
      const userWallets = await Wallet.find({ owner_type: 'user' });
      const merchantWallets = await Wallet.find({ owner_type: { $in: ['merchant_pending', 'merchant_available'] } });
      const escrowCount = await Escrow.aggregate([{ $match: { status: 'Held' } }]);
      const userBmc = fromMinor(userWallets.reduce((s, w) => s + w.balance_minor_cache, 0));
      const merchantBmc = fromMinor(merchantWallets.reduce((s, w) => s + w.balance_minor_cache, 0));
      const lastRecon = await Reconciliation.findOne({}).sort({ created_at: -1 });
      const totalBmc = userBmc + merchantBmc;
      data = {
        totalBmc, userBmc, merchantBmc, escrowBmc: 0,
        expectedReserveBdt: totalBmc * settings.coin_rate_bdt,
        reportedReserveBdt: lastRecon ? lastRecon.provider_total * settings.coin_rate_bdt : 0,
        variance: lastRecon ? (lastRecon.variance * settings.coin_rate_bdt) : 0,
        lastReconciliation: lastRecon ? fmtDate(lastRecon.created_at) : null,
      };
    }

    if (page === 'reconciliation' && u.role === 'admin') {
      const runs = await Reconciliation.find({}).sort({ created_at: -1 }).limit(50);
      data = { runs: runs.map((r) => ({ ref: r.ref, ledgerTotal: r.ledger_total, providerTotal: r.provider_total, variance: r.variance, status: r.status, date: fmtDate(r.created_at) })) };
    }

    if (page === 'risk-alerts' && u.role === 'admin') {
      const alerts = await RiskAlert.find({}).sort({ created_at: -1 }).limit(150);
      data = { alerts: alerts.map((a) => ({ id: a._id, ref: a.ref, type: a.type, subject: `${a.subject_type}:${a.subject_id}`, severity: a.severity, status: a.status, date: fmtDate(a.created_at) })) };
    }

    if (page === 'audit-logs' && u.role === 'admin') {
      const logs = await AuditLog.find({}).sort({ created_at: -1 }).limit(200);
      data = { logs: await Promise.all(logs.map(async (l) => { let actorName = 'System'; if (l.actor_id) { const a = await User.findById(l.actor_id); actorName = a ? a.full_name : 'Unknown'; } return { actor: actorName, action: l.action, target: `${l.target_type}:${l.target_id}`, ip: l.ip, date: fmtDate(l.created_at) }; })) };
    }

    if (page === 'system-settings' && u.role === 'admin') {
      data = { settings, integrityResult: null };
    }

    if (page === 'payment-providers' && u.role === 'admin') {
      const fields = ['PAYMENT_PROVIDER', 'PAYMENT_API_KEY', 'PAYMENT_API_SECRET', 'PAYMENT_WEBHOOK_SECRET'].map((f) => ({ name: f, set: !!process.env[f] }));
      data = { fields, active: !!activePaymentDriver() && IS_PROD, testMode: !IS_PROD };
    }

    if (page === 'settlement-providers' && u.role === 'admin') {
      const fields = ['SETTLEMENT_PROVIDER', 'SETTLEMENT_API_KEY', 'SETTLEMENT_API_SECRET', 'SETTLEMENT_WEBHOOK_SECRET'].map((f) => ({ name: f, set: !!process.env[f] }));
      data = { fields, active: !!activeSettlementDriver() && IS_PROD, testMode: !IS_PROD };
    }

    if (page === 'profile') data = {};

    res.render('app', {
      page, role: u.role, user: { full_name: u.full_name, email: u.email, phone: u.phone },
      data, query: req.query, unreadCount, csrfToken: res.locals.csrfToken, flash: req.session.flash || null,
    });
    req.session.flash = null;
  } catch (e) { next(e); }
});

app.get('/app/transactions/:txId', requireAuth, requireRole('user', 'merchant', 'admin'), async (req, res, next) => {
  try {
    const u = currentUser(req);
    const t = await Transaction.findOne({ tx_id: req.params.txId });
    if (!t) return res.status(404).send('Transaction not found.');
    if (u.role === 'user' && String(t.user_id) !== u.id) return res.status(403).send('403 Forbidden');
    if (u.role === 'merchant') { const m = await getMerchantForUser(u.id); if (!m || String(t.merchant_id) !== String(m._id)) return res.status(403).send('403 Forbidden'); }
    let counterparty = '—';
    if (t.merchant_id) { const m = await Merchant.findById(t.merchant_id); counterparty = m ? m.business_name : '—'; }
    res.render('app', {
      page: 'transaction-detail', role: u.role, user: { full_name: u.full_name, email: u.email, phone: u.phone },
      data: { tx: { tx_id: t.tx_id, type: t.type, counterparty, amount_bmc: decToNum(t.amount_bmc), amount_bdt: decToNum(t.amount_bdt), rate_bdt: t.rate_bdt, status: t.status, date: fmtDate(t.created_at) } },
      query: req.query, unreadCount: await unreadNotificationCount(u.id), csrfToken: res.locals.csrfToken, flash: null,
    });
  } catch (e) { next(e); }
});

app.get('/app/disputes/:ref', requireAuth, requireRole('user', 'merchant', 'admin'), async (req, res, next) => {
  try {
    const u = currentUser(req);
    const d = await Dispute.findOne({ ref: req.params.ref });
    if (!d) return res.status(404).send('Dispute not found.');
    res.render('app', {
      page: 'dispute-detail', role: u.role, user: { full_name: u.full_name, email: u.email, phone: u.phone },
      data: { dispute: { ref: d.ref, status: d.status, reason: d.reason } },
      query: req.query, unreadCount: await unreadNotificationCount(u.id), csrfToken: res.locals.csrfToken, flash: null,
    });
  } catch (e) { next(e); }
});

/* ============================================================
 * SECTION: DEPOSIT / PAYMENT API ROUTES
 * ============================================================ */
app.post('/api/deposits/create', requireAuth, requireRole('user'), financialLimiter, csrfGuard,
  body('amount_bdt').isFloat({ gt: 0 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Invalid amount.' });
      const u = currentUser(req);
      const settings = await getSystemSettings();
      const amountBdt = Number(req.body.amount_bdt);
      if (amountBdt < settings.minimum_deposit || amountBdt > settings.maximum_deposit) {
        return res.status(400).json({ error: `Amount must be between ${settings.minimum_deposit} and ${settings.maximum_deposit} BDT.` });
      }
      if (settings.maintenance_mode) return res.status(503).json({ error: 'The platform is under maintenance. Please try again later.' });

      const driver = activePaymentDriver();
      if (!driver) return res.status(503).json({ error: 'Payments are temporarily unavailable: no live payment provider is configured.' });

      const reference = newRef('DEP');
      const rate = settings.coin_rate_bdt;
      const amountBmc = amountBdt / rate;
      const deposit = await Deposit.create({
        reference, user_id: u.id, amount_bdt: dec(amountBdt), amount_bmc: dec(amountBmc), rate_bdt: rate,
        provider: process.env.PAYMENT_PROVIDER || 'test', status: 'Pending',
      });
      const providerResult = await driver.createPayment({ amountBdt, reference });
      deposit.provider_payment_id = providerResult.providerPaymentId;
      deposit.status = 'Processing';
      await deposit.save();
      await auditLog(req, 'deposit_intent_created', 'Deposit', deposit._id, { amountBdt });

      req.session.flash = { type: 'info', message: 'Deposit initiated. It will complete once payment is confirmed.' };
      if (!IS_PROD && providerResult.redirectUrl) return res.redirect(providerResult.redirectUrl);
      res.redirect('/app/add-money');
    } catch (e) { next(e); }
  });

app.post('/api/webhooks/payment', express.raw({ type: '*/*', limit: '200kb' }), async (req, res) => {
  try {
    const rawBody = req.body instanceof Buffer ? req.body.toString('utf8') : JSON.stringify(req.body || {});
    const driver = activePaymentDriver();
    if (!driver) return res.status(503).json({ error: 'No payment provider configured.' });

    let payload;
    let simulateRef = req.query.simulate ? req.query.ref : null;
    if (simulateRef) {
      payload = { event_id: `SIM-${simulateRef}`, reference: simulateRef, status: 'Completed', amount_bdt: null };
    } else {
      const signature = req.headers['x-webhook-signature'];
      const valid = await driver.verifyWebhookSignature(rawBody, signature);
      if (!valid) return res.status(400).json({ error: 'Invalid webhook signature.' });
      try { payload = JSON.parse(rawBody); } catch (e) { return res.status(400).json({ error: 'Invalid payload.' }); }
    }

    if (!payload.event_id || !payload.reference) return res.status(400).json({ error: 'Missing event identifiers.' });

    const payloadHash = crypto.createHash('sha256').update(rawBody || JSON.stringify(payload)).digest('hex');
    const existingEvent = await WebhookEvent.findOne({ provider: 'payment', event_id: payload.event_id });
    if (existingEvent && existingEvent.processed) {
      return res.status(200).json({ status: 'already_processed' });
    }
    if (!existingEvent) {
      await WebhookEvent.create({ provider: 'payment', event_id: payload.event_id, payload_hash: payloadHash, processed: false });
    }

    const deposit = await Deposit.findOne({ reference: payload.reference });
    if (!deposit) return res.status(404).json({ error: 'Deposit reference not found.' });
    if (deposit.status === 'Completed') {
      await WebhookEvent.updateOne({ provider: 'payment', event_id: payload.event_id }, { processed: true });
      return res.status(200).json({ status: 'already_completed' });
    }
    if (payload.status !== 'Completed') {
      deposit.status = 'Failed';
      await deposit.save();
      await WebhookEvent.updateOne({ provider: 'payment', event_id: payload.event_id }, { processed: true });
      return res.status(200).json({ status: 'recorded_failed' });
    }

    const mongoSession = await mongoose.startSession();
    try {
      await mongoSession.withTransaction(async () => {
        const wallet = await getOrCreateWallet(deposit.user_id, 'user', mongoSession);
        const platformReserve = await getOrCreateWallet('000000000000000000000000', 'platform_reserve', mongoSession).catch(async () => {
          return getOrCreateWallet(new mongoose.Types.ObjectId('000000000000000000000000'), 'platform_reserve', mongoSession);
        });
        const txId = newRef('TXN');
        const amountBmcMinor = toMinor(decToNum(deposit.amount_bmc));
        await postDoubleEntry(mongoSession, {
          transactionId: txId, debitWalletId: platformReserve._id, creditWalletId: wallet._id,
          amountBmcMinor, rateBdt: deposit.rate_bdt, entryType: 'Deposit', reference: deposit.reference,
        });
        await Transaction.create([{
          tx_id: txId, type: 'Deposit', user_id: deposit.user_id, amount_bmc: deposit.amount_bmc, amount_bdt: deposit.amount_bdt,
          rate_bdt: deposit.rate_bdt, status: 'Completed', reference: deposit.reference,
        }], { session: mongoSession });
        deposit.status = 'Completed';
        deposit.tx_id = txId;
        await deposit.save({ session: mongoSession });
      });
      await WebhookEvent.updateOne({ provider: 'payment', event_id: payload.event_id }, { processed: true });
      await notify(deposit.user_id, 'user', 'Deposit', 'Deposit Completed', `Your deposit of ${decToNum(deposit.amount_bdt)} BDT has been credited.`);
      await riskCheck('user', deposit.user_id, 'large_transaction', { amountBdt: decToNum(deposit.amount_bdt) });
      res.status(200).json({ status: 'completed' });
    } finally {
      mongoSession.endSession();
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('[BMA] webhook error:', e.message);
    res.status(500).json({ error: 'Webhook processing failed.' });
  }
});

/* ============================================================
 * SECTION: QR PAYMENT
 * ============================================================ */
app.post('/api/qr/pay', requireAuth, requireRole('user'), financialLimiter, csrfGuard,
  body('merchant_ref').trim().notEmpty(),
  body('amount_bdt').isFloat({ gt: 0 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).send('Invalid payment request.');
      const u = currentUser(req);
      const settings = await getSystemSettings();
      if (settings.maintenance_mode) return res.status(503).send('The platform is under maintenance.');

      const merchant = await Merchant.findOne({ merchant_ref: req.body.merchant_ref });
      if (!merchant) return res.status(404).send('Merchant not found.');
      if (merchant.status !== 'Approved') return res.status(403).send('This merchant cannot receive payments at this time.');

      const amountBdt = Number(req.body.amount_bdt);
      const rate = settings.coin_rate_bdt;
      const amountBmcMinor = bmcFromBdtMinor(toMinor(amountBdt), rate);

      const startDay = new Date(); startDay.setHours(0, 0, 0, 0);
      const dayPayments = await Payment.find({ user_id: u.id, status: 'Completed', created_at: { $gte: startDay } });
      const dayTotal = dayPayments.reduce((s, p) => s + decToNum(p.amount_bmc), 0);
      if (dayTotal + fromMinor(amountBmcMinor) > settings.daily_payment_limit) {
        return res.status(400).send('Daily payment limit exceeded.');
      }

      const idemKey = req.headers['idempotency-key'] || newRef('QRPAY');
      const result = await withIdempotency(idemKey, 'qr_payment', { userId: u.id, merchantRef: merchant.merchant_ref, amountBdt }, async () => {
        const userWallet = await getOrCreateWallet(u.id, 'user');
        if (userWallet.balance_minor_cache < amountBmcMinor) {
          const err = new Error('INSUFFICIENT_FUNDS'); err.code = 'INSUFFICIENT_FUNDS'; throw err;
        }
        const mongoSession = await mongoose.startSession();
        let txId, paymentDoc;
        try {
          await mongoSession.withTransaction(async () => {
            const uWallet = await getOrCreateWallet(u.id, 'user', mongoSession);
            const pendingWallet = await getOrCreateWallet(merchant._id, 'merchant_pending', mongoSession);
            txId = newRef('TXN');
            await postDoubleEntry(mongoSession, {
              transactionId: txId, debitWalletId: uWallet._id, creditWalletId: pendingWallet._id,
              amountBmcMinor, rateBdt: rate, entryType: 'Payment', reference: `QR payment to ${merchant.business_name}`,
            });
            const created = await Payment.create([{
              reference: newRef('PAY'), user_id: u.id, merchant_id: merchant._id,
              amount_bmc: dec(fromMinor(amountBmcMinor)), amount_bdt: dec(amountBdt), rate_bdt: rate, status: 'Completed', tx_id: txId,
            }], { session: mongoSession });
            paymentDoc = created[0];
            await Transaction.create([{
              tx_id: txId, type: 'Payment', user_id: u.id, merchant_id: merchant._id,
              amount_bmc: dec(fromMinor(amountBmcMinor)), amount_bdt: dec(amountBdt), rate_bdt: rate, status: 'Completed', reference: paymentDoc.reference,
            }], { session: mongoSession });
            await Escrow.create([{ payment_id: paymentDoc._id, merchant_id: merchant._id, amount_bmc: dec(fromMinor(amountBmcMinor)), status: 'Held' }], { session: mongoSession });
          });
        } catch (err) {
          if (err.message === 'INSUFFICIENT_FUNDS') { const e2 = new Error('INSUFFICIENT_FUNDS'); e2.code = 'INSUFFICIENT_FUNDS'; throw e2; }
          throw err;
        } finally { mongoSession.endSession(); }
        return { txId };
      });

      await notify(u.id, 'user', 'Payment', 'Payment Successful', `You paid ${amountBdt} BDT to ${merchant.business_name}.`);
      const merchantUser = await User.findById(merchant.user_id);
      if (merchantUser) await notify(merchantUser._id, 'merchant', 'Payment', 'Payment Received', `You received a payment of ${amountBdt} BDT (pending release).`);
      await riskCheck('user', u.id, 'large_transaction', { amountBdt });
      await auditLog(req, 'qr_payment', 'Transaction', result.txId, { amountBdt, merchant: merchant.merchant_ref });
      res.redirect(`/app/transactions/${result.txId}`);
    } catch (e) {
      if (e.code === 'INSUFFICIENT_FUNDS') return res.status(400).send('Insufficient wallet balance.');
      if (e.code === 'IDEMPOTENCY_CONFLICT') return res.status(409).send('Duplicate request with different parameters was rejected.');
      next(e);
    }
  });

/* ============================================================
 * SECTION: ORDERS / ESCROW RELEASE (merchant fulfills order)
 * ============================================================ */
app.post('/api/orders/:orderId/complete', requireAuth, requireRole('merchant'), csrfGuard, async (req, res, next) => {
  try {
    const u = currentUser(req);
    const merchant = await getMerchantForUser(u.id);
    const order = await Order.findOne({ order_id: req.params.orderId, merchant_id: merchant._id });
    if (!order) return res.status(404).send('Order not found.');
    const escrow = await Escrow.findOne({ order_id: order._id, status: 'Held' });
    if (!escrow) return res.status(400).send('No escrow held for this order, or it was already released/refunded.');

    const mongoSession = await mongoose.startSession();
    try {
      await mongoSession.withTransaction(async () => {
        const settings = await getSystemSettings();
        const pendingWallet = await getOrCreateWallet(merchant._id, 'merchant_pending', mongoSession);
        const availableWallet = await getOrCreateWallet(merchant._id, 'merchant_available', mongoSession);
        const amountBmcMinor = toMinor(decToNum(escrow.amount_bmc));
        await postDoubleEntry(mongoSession, {
          transactionId: newRef('TXN'), debitWalletId: pendingWallet._id, creditWalletId: availableWallet._id,
          amountBmcMinor, rateBdt: settings.coin_rate_bdt, entryType: 'Escrow', reference: `Escrow release for order ${order.order_id}`,
        });
        escrow.status = 'Released';
        escrow.released_at = new Date();
        await escrow.save({ session: mongoSession });
        order.status = 'Completed';
        order.fulfillment_status = 'Completed';
        await order.save({ session: mongoSession });
      });
    } finally { mongoSession.endSession(); }

    await auditLog(req, 'escrow_release', 'Order', order.order_id);
    res.redirect('/app/orders');
  } catch (e) { next(e); }
});

/* ============================================================
 * SECTION: REFUNDS
 * ============================================================ */
app.post('/api/refunds/create', requireAuth, requireRole('user'), financialLimiter, csrfGuard,
  body('tx_id').trim().notEmpty(), body('reason').trim().isLength({ min: 3, max: 500 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).send('Please provide a valid transaction and reason.');
      const u = currentUser(req);
      const tx = await Transaction.findOne({ tx_id: req.body.tx_id, user_id: u.id, type: 'Payment', status: 'Completed' });
      if (!tx) return res.status(404).send('Original payment transaction not found.');
      const existingRefund = await Refund.findOne({ original_tx_id: tx.tx_id, status: { $in: ['Requested', 'Approved', 'Processing', 'Completed'] } });
      if (existingRefund) return res.status(409).send('A refund for this transaction already exists.');

      const refund = await Refund.create({
        ref: newRef('RFD'), user_id: u.id, merchant_id: tx.merchant_id, original_tx_id: tx.tx_id,
        amount_bmc: tx.amount_bmc, amount_bdt: tx.amount_bdt, reason: req.body.reason, status: 'Requested',
      });
      await auditLog(req, 'refund_requested', 'Refund', refund.ref);
      req.session.flash = { type: 'success', message: 'Refund request submitted.' };
      res.redirect('/app/refunds');
    } catch (e) { next(e); }
  });

app.post('/api/refunds/:ref/decision', requireAuth, requireRole('admin'), csrfGuard,
  body('decision').isIn(['approve', 'reject']),
  async (req, res, next) => {
    try {
      const refund = await Refund.findOne({ ref: req.params.ref });
      if (!refund) return res.status(404).send('Refund not found.');
      if (refund.status !== 'Requested') return res.status(409).send('This refund has already been processed.');

      if (req.body.decision === 'reject') {
        refund.status = 'Rejected';
        await refund.save();
        await notify(refund.user_id, 'user', 'Refund', 'Refund Rejected', `Your refund request ${refund.ref} was rejected.`);
        await auditLog(req, 'refund_rejected', 'Refund', refund.ref);
        return res.redirect('/app/refunds');
      }

      const tx = await Transaction.findOne({ tx_id: refund.original_tx_id });
      if (!tx) return res.status(404).send('Original transaction missing.');
      const amountBmcMinor = toMinor(decToNum(refund.amount_bmc));

      const mongoSession = await mongoose.startSession();
      try {
        await mongoSession.withTransaction(async () => {
          const userWallet = await getOrCreateWallet(refund.user_id, 'user', mongoSession);
          const escrow = await Escrow.findOne({ payment_id: (await Payment.findOne({ tx_id: tx.tx_id }))._id }).session(mongoSession);
          let sourceWalletType = 'merchant_pending';
          if (escrow && escrow.status === 'Released') sourceWalletType = 'merchant_available';
          const merchantWallet = await getOrCreateWallet(refund.merchant_id, sourceWalletType, mongoSession);

          await postDoubleEntry(mongoSession, {
            transactionId: newRef('TXN'), debitWalletId: merchantWallet._id, creditWalletId: userWallet._id,
            amountBmcMinor, rateBdt: tx.rate_bdt, entryType: 'Refund', reference: `Refund for ${tx.tx_id}`,
          });
          if (escrow && escrow.status === 'Held') { escrow.status = 'Refunded'; await escrow.save({ session: mongoSession }); }

          refund.status = 'Completed';
          await refund.save({ session: mongoSession });
          await Transaction.create([{
            tx_id: newRef('TXN'), type: 'Refund', user_id: refund.user_id, merchant_id: refund.merchant_id,
            amount_bmc: refund.amount_bmc, amount_bdt: refund.amount_bdt, rate_bdt: tx.rate_bdt, status: 'Completed', reference: refund.ref,
          }], { session: mongoSession });
        });
      } finally { mongoSession.endSession(); }

      await notify(refund.user_id, 'user', 'Refund', 'Refund Completed', `Your refund ${refund.ref} has been credited to your wallet.`);
      await auditLog(req, 'refund_approved', 'Refund', refund.ref);
      res.redirect('/app/refunds');
    } catch (e) { next(e); }
  });

/* ============================================================
 * SECTION: DISPUTES
 * ============================================================ */
app.post('/api/disputes/create', requireAuth, requireRole('user'), csrfGuard,
  body('tx_id').trim().notEmpty(), body('reason').trim().isLength({ min: 3, max: 1000 }),
  async (req, res, next) => {
    try {
      const u = currentUser(req);
      const tx = await Transaction.findOne({ tx_id: req.body.tx_id, user_id: u.id });
      if (!tx) return res.status(404).send('Transaction not found.');
      const dispute = await Dispute.create({ ref: newRef('DSP'), user_id: u.id, merchant_id: tx.merchant_id, tx_id: tx.tx_id, reason: req.body.reason, status: 'Open' });
      if (tx.merchant_id) { const m = await Merchant.findById(tx.merchant_id); if (m) { const mu = await User.findById(m.user_id); if (mu) await notify(mu._id, 'merchant', 'Dispute', 'New Dispute Opened', `A dispute was opened for transaction ${tx.tx_id}.`); } }
      await auditLog(req, 'dispute_opened', 'Dispute', dispute.ref);
      res.redirect('/app/disputes');
    } catch (e) { next(e); }
  });

app.post('/api/disputes/:ref/respond', requireAuth, requireRole('merchant'), csrfGuard, body('response').trim().isLength({ min: 3, max: 1000 }), async (req, res, next) => {
  try {
    const dispute = await Dispute.findOne({ ref: req.params.ref });
    if (!dispute) return res.status(404).send('Dispute not found.');
    dispute.merchant_response = req.body.response;
    dispute.status = 'Merchant Responded';
    await dispute.save();
    await auditLog(req, 'dispute_response', 'Dispute', dispute.ref);
    res.redirect(`/app/disputes/${dispute.ref}`);
  } catch (e) { next(e); }
});

app.post('/api/admin/disputes/:ref/resolve', requireAuth, requireRole('admin'), csrfGuard, body('resolution').isIn(['Approved', 'Rejected']), async (req, res, next) => {
  try {
    const dispute = await Dispute.findOne({ ref: req.params.ref });
    if (!dispute) return res.status(404).send('Dispute not found.');
    dispute.status = 'Resolved';
    dispute.resolution = req.body.resolution;
    await dispute.save();
    await auditLog(req, 'dispute_resolved', 'Dispute', dispute.ref, { resolution: req.body.resolution });
    res.redirect(`/app/disputes/${dispute.ref}`);
  } catch (e) { next(e); }
});

/* ============================================================
 * SECTION: SETTLEMENT (merchant + engine)
 * ============================================================ */
app.post('/api/merchant/auto-settlement', requireAuth, requireRole('merchant'), csrfGuard, async (req, res, next) => {
  try {
    const u = currentUser(req);
    const merchant = await getMerchantForUser(u.id);
    merchant.auto_settlement.enabled = !!req.body.enabled;
    merchant.auto_settlement.frequency = req.body.frequency;
    merchant.auto_settlement.min_amount = Math.max(1, Number(req.body.min_amount) || merchant.auto_settlement.min_amount);
    await merchant.save();
    await auditLog(req, 'auto_settlement_updated', 'Merchant', merchant._id, req.body);
    res.redirect('/app/auto-settlement');
  } catch (e) { next(e); }
});

async function createSettlementForMerchant(merchant, settings) {
  const availWallet = await getOrCreateWallet(merchant._id, 'merchant_available');
  const amountBmcMinor = availWallet.balance_minor_cache;
  if (fromMinor(amountBmcMinor) < merchant.auto_settlement.min_amount) return null;

  const driver = activeSettlementDriver();
  if (!driver) {
    await RiskAlert.create({ ref: newRef('RISK'), type: 'settlement_provider_missing', subject_type: 'merchant', subject_id: String(merchant._id), severity: 'Under Review', status: 'Open', details: {} });
    return null;
  }

  const reference = newRef('STL');
  const settlement = await Settlement.create({
    ref: reference, merchant_id: merchant._id, amount_bmc: dec(fromMinor(amountBmcMinor)),
    amount_bdt: dec(fromMinor(amountBmcMinor) * settings.coin_rate_bdt), rate_bdt: settings.coin_rate_bdt,
    status: 'Pending', provider: process.env.SETTLEMENT_PROVIDER || 'test',
  });

  const mongoSession = await mongoose.startSession();
  try {
    await mongoSession.withTransaction(async () => {
      const escrowWallet = await getOrCreateWallet(merchant._id, 'escrow', mongoSession);
      await postDoubleEntry(mongoSession, {
        transactionId: newRef('TXN'), debitWalletId: availWallet._id, creditWalletId: escrowWallet._id,
        amountBmcMinor, rateBdt: settings.coin_rate_bdt, entryType: 'Settlement', reference,
      });
    });
  } finally { mongoSession.endSession(); }

  settlement.status = 'Processing';
  await settlement.save();

  try {
    const providerResult = await driver.createSettlement({ amountBdt: fromMinor(amountBmcMinor) * settings.coin_rate_bdt, reference });
    settlement.provider_settlement_id = providerResult.providerSettlementId;
    settlement.status = providerResult.status || 'Processing';
    await settlement.save();
  } catch (e) {
    settlement.status = 'Failed';
    await settlement.save();
  }
  return settlement;
}

app.post('/api/settlements/request', requireAuth, requireRole('merchant'), financialLimiter, csrfGuard, async (req, res, next) => {
  try {
    const u = currentUser(req);
    const merchant = await getMerchantForUser(u.id);
    const settings = await getSystemSettings();
    const settlement = await createSettlementForMerchant(merchant, settings);
    if (!settlement) { req.session.flash = { type: 'warning', message: 'Settlement could not be created: minimum balance not met or no provider configured.' }; }
    else { await auditLog(req, 'settlement_requested', 'Settlement', settlement.ref); }
    res.redirect('/app/settlement');
  } catch (e) { next(e); }
});

app.post('/api/webhooks/settlement', express.raw({ type: '*/*', limit: '200kb' }), async (req, res) => {
  try {
    const rawBody = req.body instanceof Buffer ? req.body.toString('utf8') : JSON.stringify(req.body || {});
    let payload;
    try { payload = JSON.parse(rawBody); } catch (e) { return res.status(400).json({ error: 'Invalid payload.' }); }
    if (!payload.event_id || !payload.reference) return res.status(400).json({ error: 'Missing identifiers.' });

    const existingEvent = await WebhookEvent.findOne({ provider: 'settlement', event_id: payload.event_id });
    if (existingEvent && existingEvent.processed) return res.status(200).json({ status: 'already_processed' });
    if (!existingEvent) await WebhookEvent.create({ provider: 'settlement', event_id: payload.event_id, payload_hash: crypto.createHash('sha256').update(rawBody).digest('hex'), processed: false });

    const settlement = await Settlement.findOne({ ref: payload.reference });
    if (!settlement) return res.status(404).json({ error: 'Settlement not found.' });
    if (settlement.status === 'Completed' || settlement.status === 'Failed') {
      await WebhookEvent.updateOne({ provider: 'settlement', event_id: payload.event_id }, { processed: true });
      return res.status(200).json({ status: 'already_final' });
    }
    settlement.status = payload.status === 'Completed' ? 'Completed' : 'Failed';
    await settlement.save();
    if (settlement.status === 'Failed') {
      const mongoSession = await mongoose.startSession();
      try {
        await mongoSession.withTransaction(async () => {
          const escrowWallet = await getOrCreateWallet(settlement.merchant_id, 'escrow', mongoSession);
          const availWallet = await getOrCreateWallet(settlement.merchant_id, 'merchant_available', mongoSession);
          await postDoubleEntry(mongoSession, {
            transactionId: newRef('TXN'), debitWalletId: escrowWallet._id, creditWalletId: availWallet._id,
            amountBmcMinor: toMinor(decToNum(settlement.amount_bmc)), rateBdt: settlement.rate_bdt, entryType: 'Adjustment', reference: `Settlement reversal ${settlement.ref}`,
          });
        });
      } finally { mongoSession.endSession(); }
    }
    await WebhookEvent.updateOne({ provider: 'settlement', event_id: payload.event_id }, { processed: true });
    const merchant = await Merchant.findById(settlement.merchant_id);
    if (merchant) { const mu = await User.findById(merchant.user_id); if (mu) await notify(mu._id, 'merchant', 'Settlement', `Settlement ${settlement.status}`, `Settlement ${settlement.ref} is now ${settlement.status}.`); }
    res.status(200).json({ status: 'ok' });
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('[BMA] settlement webhook error:', e.message);
    res.status(500).json({ error: 'Webhook processing failed.' });
  }
});

/* ============================================================
 * SECTION: KYC / KYB
 * ============================================================ */
app.post('/api/kyc/submit', requireAuth, requireRole('user'), csrfGuard, async (req, res, next) => {
  try {
    const u = currentUser(req);
    const userDoc = await User.findById(u.id);
    let kyc = await KYC.findOne({ user_id: u.id });
    if (!kyc) kyc = new KYC({ user_id: u.id });
    kyc.full_name = userDoc.full_name;
    kyc.phone = userDoc.phone;
    kyc.email = userDoc.email;
    kyc.date_of_birth = req.body.date_of_birth;
    kyc.address = req.body.address;
    kyc.identification_type = req.body.identification_type;
    kyc.identification_number = req.body.identification_number;
    kyc.status = 'Pending';
    kyc.submitted_at = new Date();
    await kyc.save();
    await auditLog(req, 'kyc_submitted', 'KYC', kyc._id);
    res.redirect('/app/kyc');
  } catch (e) { next(e); }
});

app.post('/api/admin/kyc/:id/decision', requireAuth, requireRole('admin'), csrfGuard, body('decision').isIn(['approve', 'reject']), async (req, res, next) => {
  try {
    const kyc = await KYC.findById(req.params.id);
    if (!kyc) return res.status(404).send('KYC record not found.');
    const u = currentUser(req);
    kyc.status = req.body.decision === 'approve' ? 'Verified' : 'Rejected';
    kyc.verified_at = new Date();
    kyc.reviewed_by = u.id;
    await kyc.save();
    await notify(kyc.user_id, 'user', 'KYC', `KYC ${kyc.status}`, `Your identity verification is now ${kyc.status}.`);
    await auditLog(req, 'kyc_decision', 'KYC', kyc._id, { decision: req.body.decision });
    res.redirect('/app/kyc');
  } catch (e) { next(e); }
});

app.post('/api/kyb/submit', requireAuth, requireRole('merchant'), csrfGuard, async (req, res, next) => {
  try {
    const u = currentUser(req);
    const merchant = await getMerchantForUser(u.id);
    let kyb = await KYB.findOne({ merchant_id: merchant._id });
    if (!kyb) kyb = new KYB({ merchant_id: merchant._id });
    kyb.business_name = req.body.business_name;
    kyb.owner_name = merchant.owner_name;
    kyb.business_type = req.body.business_type;
    kyb.business_address = req.body.business_address;
    kyb.trade_license_metadata = { number: req.body.trade_license_number };
    kyb.status = 'Pending';
    kyb.submitted_at = new Date();
    await kyb.save();
    merchant.business_name = req.body.business_name;
    merchant.business_type = req.body.business_type;
    merchant.business_address = req.body.business_address;
    merchant.status = 'Under Review';
    await merchant.save();
    await auditLog(req, 'kyb_submitted', 'KYB', kyb._id);
    res.redirect('/app/kyb');
  } catch (e) { next(e); }
});

app.post('/api/admin/kyb/:id/decision', requireAuth, requireRole('admin'), csrfGuard, body('decision').isIn(['approve', 'reject']), async (req, res, next) => {
  try {
    const kyb = await KYB.findById(req.params.id);
    if (!kyb) return res.status(404).send('KYB record not found.');
    const u = currentUser(req);
    const merchant = await Merchant.findById(kyb.merchant_id);
    kyb.status = req.body.decision === 'approve' ? 'Approved' : 'Rejected';
    kyb.verified_at = new Date();
    kyb.reviewed_by = u.id;
    await kyb.save();
    if (merchant) {
      merchant.status = req.body.decision === 'approve' ? 'Approved' : 'Rejected';
      await merchant.save();
      const mu = await User.findById(merchant.user_id);
      if (mu) await notify(mu._id, 'merchant', 'KYB', `KYB ${kyb.status}`, `Your business verification is now ${kyb.status}.`);
    }
    await auditLog(req, 'kyb_decision', 'KYB', kyb._id, { decision: req.body.decision });
    res.redirect('/app/kyb');
  } catch (e) { next(e); }
});

/* ============================================================
 * SECTION: NOTIFICATIONS / PROFILE / SECURITY
 * ============================================================ */
app.post('/api/notifications/:id/read', requireAuth, csrfGuard, async (req, res, next) => {
  try {
    const u = currentUser(req);
    await Notification.updateOne({ _id: req.params.id, owner_id: u.id }, { $set: { read: true } });
    res.redirect('/app/notifications');
  } catch (e) { next(e); }
});

app.post('/api/profile/update', requireAuth, csrfGuard, body('full_name').trim().isLength({ min: 2, max: 120 }), body('phone').trim().isLength({ min: 6, max: 32 }), async (req, res, next) => {
  try {
    const u = currentUser(req);
    const userDoc = await User.findById(u.id);
    userDoc.full_name = req.body.full_name;
    userDoc.phone = req.body.phone;
    await userDoc.save();
    req.session.user.full_name = userDoc.full_name;
    req.session.user.phone = userDoc.phone;
    await auditLog(req, 'profile_updated', 'User', u.id);
    res.redirect('/app/profile');
  } catch (e) { next(e); }
});

app.post('/api/security/change-password', requireAuth, csrfGuard, body('current_password').notEmpty(), body('new_password').isLength({ min: 8, max: 128 }), async (req, res, next) => {
  try {
    const u = currentUser(req);
    const userDoc = await User.findById(u.id);
    const ok = await verifyPassword(req.body.current_password, userDoc.password_hash);
    if (!ok) return res.status(400).send('Current password is incorrect.');
    userDoc.password_hash = await hashPassword(req.body.new_password);
    await userDoc.save();
    await notify(u.id, u.role, 'Security', 'Password Changed', 'Your account password was changed successfully.');
    await auditLog(req, 'password_changed', 'User', u.id);
    res.redirect('/app/security');
  } catch (e) { next(e); }
});

app.post('/api/security/sessions/:id/revoke', requireAuth, csrfGuard, async (req, res, next) => {
  try {
    const u = currentUser(req);
    await DeviceSession.updateOne({ _id: req.params.id, user_id: u.id }, { revoked: true });
    await auditLog(req, 'session_revoked', 'DeviceSession', req.params.id);
    res.redirect('/app/security');
  } catch (e) { next(e); }
});

/* ============================================================
 * SECTION: ADMIN ROUTES
 * ============================================================ */
app.post('/api/admin/users/:id/status', requireAuth, requireRole('admin'), csrfGuard, body('status').isIn(['active', 'frozen', 'suspended']), async (req, res, next) => {
  try {
    const userDoc = await User.findById(req.params.id);
    if (!userDoc) return res.status(404).send('User not found.');
    userDoc.status = req.body.status;
    await userDoc.save();
    await auditLog(req, 'user_status_changed', 'User', userDoc._id, { status: req.body.status });
    await notify(userDoc._id, userDoc.role, 'Admin announcement', 'Account Status Updated', `Your account status is now ${req.body.status}.`);
    res.redirect('/app/users');
  } catch (e) { next(e); }
});

app.post('/api/admin/merchants/:id/status', requireAuth, requireRole('admin'), csrfGuard, body('status').isIn(['Approved', 'Suspended', 'Frozen', 'Rejected', 'Under Review', 'Pending']), async (req, res, next) => {
  try {
    const merchant = await Merchant.findById(req.params.id);
    if (!merchant) return res.status(404).send('Merchant not found.');
    merchant.status = req.body.status;
    await merchant.save();
    await auditLog(req, 'merchant_status_changed', 'Merchant', merchant._id, { status: req.body.status });
    const mu = await User.findById(merchant.user_id);
    if (mu) await notify(mu._id, 'merchant', 'Admin announcement', 'Merchant Status Updated', `Your merchant status is now ${req.body.status}.`);
    res.redirect('/app/merchants');
  } catch (e) { next(e); }
});

app.post('/api/admin/reconciliation/run', requireAuth, requireRole('admin'), csrfGuard, async (req, res, next) => {
  try {
    const record = await runReconciliation();
    await auditLog(req, 'reconciliation_run', 'Reconciliation', record.ref, { variance: record.variance });
    res.redirect('/app/reconciliation');
  } catch (e) { next(e); }
});

app.post('/api/admin/risk-alerts/:id/resolve', requireAuth, requireRole('admin'), csrfGuard, async (req, res, next) => {
  try {
    await RiskAlert.updateOne({ _id: req.params.id }, { $set: { status: 'Resolved' } });
    await auditLog(req, 'risk_alert_resolved', 'RiskAlert', req.params.id);
    res.redirect('/app/risk-alerts');
  } catch (e) { next(e); }
});

app.post('/api/admin/settings/update', requireAuth, requireRole('admin'), csrfGuard, async (req, res, next) => {
  try {
    const settings = await getSystemSettings();
    const numericFields = ['coin_rate_bdt', 'minimum_deposit', 'maximum_deposit', 'daily_payment_limit', 'monthly_payment_limit'];
    numericFields.forEach((f) => { if (req.body[f] !== undefined) settings[f] = Number(req.body[f]); });
    settings.maintenance_mode = !!req.body.maintenance_mode;
    settings.registration_enabled = !!req.body.registration_enabled;
    settings.merchant_registration_enabled = !!req.body.merchant_registration_enabled;
    await settings.save();
    await auditLog(req, 'system_settings_updated', 'SystemSetting', settings._id, req.body);
    res.redirect('/app/system-settings');
  } catch (e) { next(e); }
});

app.post('/api/admin/ledger/verify', requireAuth, requireRole('admin'), csrfGuard, async (req, res, next) => {
  try {
    const result = await verifyLedgerIntegrity();
    if (!result.valid) {
      await RiskAlert.create({ ref: newRef('RISK'), type: 'ledger_integrity_error', subject_type: 'system', subject_id: result.failedAt, severity: 'Blocked', status: 'Open', details: result });
    }
    await auditLog(req, 'ledger_integrity_check', 'Ledger', 'global', result);
    const settings = await getSystemSettings();
    const u = currentUser(req);
    res.render('app', {
      page: 'system-settings', role: u.role, user: { full_name: u.full_name, email: u.email, phone: u.phone },
      data: { settings, integrityResult: result }, query: {}, unreadCount: await unreadNotificationCount(u.id), csrfToken: res.locals.csrfToken, flash: null,
    });
  } catch (e) { next(e); }
});

/**
 * Admin financial adjustment: NEVER edits wallet balance directly.
 * Creates a proper ledger adjustment/reversal transaction with full audit trail.
 */
app.post('/api/admin/adjustments/create', requireAuth, requireRole('admin'), csrfGuard,
  body('wallet_owner_id').notEmpty(), body('wallet_owner_type').isIn(['user', 'merchant_pending', 'merchant_available']),
  body('amount_bmc').isFloat(), body('direction').isIn(['debit', 'credit']), body('reason').trim().isLength({ min: 3 }),
  async (req, res, next) => {
    try {
      const u = currentUser(req);
      const settings = await getSystemSettings();
      const { wallet_owner_id, wallet_owner_type, amount_bmc, direction, reason } = req.body;
      const amountBmcMinor = toMinor(Math.abs(Number(amount_bmc)));
      const mongoSession = await mongoose.startSession();
      let txId;
      try {
        await mongoSession.withTransaction(async () => {
          const targetWallet = await getOrCreateWallet(wallet_owner_id, wallet_owner_type, mongoSession);
          const reserveWallet = await getOrCreateWallet(new mongoose.Types.ObjectId('000000000000000000000000'), 'platform_reserve', mongoSession);
          txId = newRef('TXN');
          if (direction === 'credit') {
            await postDoubleEntry(mongoSession, { transactionId: txId, debitWalletId: reserveWallet._id, creditWalletId: targetWallet._id, amountBmcMinor, rateBdt: settings.coin_rate_bdt, entryType: 'Adjustment', reference: `Admin adjustment: ${reason}` });
          } else {
            await postDoubleEntry(mongoSession, { transactionId: txId, debitWalletId: targetWallet._id, creditWalletId: reserveWallet._id, amountBmcMinor, rateBdt: settings.coin_rate_bdt, entryType: 'Adjustment', reference: `Admin adjustment: ${reason}` });
          }
          await Transaction.create([{ tx_id: txId, type: 'Adjustment', amount_bmc: dec(fromMinor(amountBmcMinor)), amount_bdt: dec(fromMinor(amountBmcMinor) * settings.coin_rate_bdt), rate_bdt: settings.coin_rate_bdt, status: 'Completed', reference: reason, metadata: { admin_id: u.id, wallet_owner_id, wallet_owner_type, direction } }], { session: mongoSession });
        });
      } finally { mongoSession.endSession(); }
      await auditLog(req, 'admin_wallet_adjustment', 'Transaction', txId, { wallet_owner_id, wallet_owner_type, amount_bmc, direction, reason });
      res.status(200).json({ status: 'completed', tx_id: txId });
    } catch (e) { next(e); }
  });

/* ============================================================
 * SECTION: ERROR HANDLING
 * ============================================================ */
app.use((req, res) => {
  res.status(404).send(`
    <!DOCTYPE html><html><head><title>404 - BMA</title>
    <style>body{font-family:Inter,sans-serif;background:#F4F7FE;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}
    .box{text-align:center;} h1{font-size:64px;color:#4F46E5;margin:0;} p{color:#6B7280;} a{color:#4F46E5;text-decoration:none;font-weight:600;}</style>
    </head><body><div class="box"><h1>404</h1><p>The page you are looking for could not be found.</p><a href="/">Return to BMA</a></div></body></html>
  `);
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  // eslint-disable-next-line no-console
  console.error('[BMA ERROR]', err && err.message, IS_PROD ? '' : err.stack);
  if (res.headersSent) return next(err);
  if (req.path.startsWith('/api/')) return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  res.status(500).send(`
    <!DOCTYPE html><html><head><title>Error - BMA</title>
    <style>body{font-family:Inter,sans-serif;background:#F4F7FE;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}
    .box{text-align:center;} h1{color:#EF4444;} p{color:#6B7280;} a{color:#4F46E5;text-decoration:none;font-weight:600;}</style>
    </head><body><div class="box"><h1>Something went wrong</h1><p>Please try again. If the problem persists, contact support.</p><a href="/">Return to BMA</a></div></body></html>
  `);
});

/* ============================================================
 * SECTION: STARTUP (serverless-safe: export app, listen only outside Vercel)
 * ============================================================ */
let bootstrapped = false;
async function bootstrap() {
  if (bootstrapped) return;
  bootstrapped = true;
  await connectDB();
  await ensureInitialAdmin();
}

// Ensure DB + admin bootstrap runs on cold start (both local and serverless invocations).
bootstrap().catch((e) => {
  // eslint-disable-next-line no-console
  console.error('[BMA] Bootstrap failed:', e.message);
});

if (!process.env.VERCEL) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`[BMA] Server running locally on port ${port}`);
  });
}

module.exports = app;
