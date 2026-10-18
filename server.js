require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const PRIVATE_DIR = path.join(ROOT, "uploads", "private");
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PRIVATE_DIR, { recursive: true });

if (process.env.TRUST_PROXY === "1") app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: false, limit: "200kb" }));
app.use(session({
  name: "waelviews.sid",
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret-before-deployment",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 1000 * 60 * 60 * 8 }
}));

const db = new SQLiteStore(path.join(DATA_DIR, "wael-views.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS services (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, platform TEXT NOT NULL,
 description TEXT NOT NULL, price INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL,
 service_id INTEGER NOT NULL, target_url TEXT NOT NULL, amount INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'awaiting_payment', payment_status TEXT NOT NULL DEFAULT 'awaiting_payment',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(service_id) REFERENCES services(id)
);
CREATE TABLE IF NOT EXISTS payments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
 method TEXT NOT NULL, sender_identifier TEXT NOT NULL, transfer_reference TEXT,
 notes TEXT, receipt_filename TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'submitted',
 review_note TEXT, reviewed_by INTEGER, reviewed_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(order_id) REFERENCES orders(id), FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER, action TEXT NOT NULL, details TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
const serviceCount = db.prepare("SELECT COUNT(*) AS n FROM services").get().n;
if (!serviceCount) {
  const ins = db.prepare("INSERT INTO services(name,platform,description,price) VALUES(?,?,?,?)");
  ins.run("حملة ترويج فيديو", "TikTok", "ترويج رسمي أو إدارة حملة نمو ملتزمة بسياسات المنصة. السعر يحدد بعد مراجعة نطاق الخدمة.", 10000);
  ins.run("حملة ترويج فيديو", "YouTube", "تخطيط حملة ترويج مدفوعة وتحسين الوصول. لا يوجد ضمان لعدد مشاهدات محدد.", 15000);
  ins.run("تحسين المحتوى", "Instagram", "تحسين الوصف والوسوم وخطة النشر.", 5000);
  ins.run("تصميم صورة مصغرة", "YouTube", "تصميم صورة مصغرة مخصصة للفيديو.", 7500);
}
const adminEmail = (process.env.ADMIN_EMAIL || "assadwael40@gmail.com").toLowerCase().trim();
const adminPassword = process.env.ADMIN_PASSWORD;
if (adminPassword && adminPassword !== "ChangeThisAdminPassword123!") {
  const existing = db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail);
  if (!existing) {
    db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')")
      .run(process.env.ADMIN_NAME || "WAEL VIEWS Admin", adminEmail, bcrypt.hashSync(adminPassword, 12));
    console.log("Initial administrator created:", adminEmail);
  } else {
    db.prepare("UPDATE users SET role='admin' WHERE email=?").run(adminEmail);
  }
} else {
  console.warn("ADMIN_PASSWORD is not configured securely. Set it in .env before using admin features.");
}

function cleanUser(user) {
  return user ? { id: user.id, name: user.name, email: user.email, role: user.role } : null;
}
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "سجّل الدخول أولًا." });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") return res.status(403).json({ error: "غير مصرح لك بالوصول." });
  next();
}
function csrfCheck(req, res, next) {
  // SameSite session cookie + same-origin API calls; production deployment should also enforce HTTPS.
  const origin = req.get("origin");
  if (origin) {
    try {
      if (new URL(origin).host !== req.get("host")) return res.status(403).json({ error: "طلب غير صالح." });
    } catch { return res.status(403).json({ error: "طلب غير صالح." }); }
  }
  next();
}
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, PRIVATE_DIR),
    filename: (_req, file, cb) => cb(null, crypto.randomBytes(18).toString("hex") + path.extname(file.originalname).toLowerCase())
  }),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const allowed = new Set(["image/jpeg", "image/png", "image/webp"]);
    if (!allowed.has(file.mimetype)) return cb(new Error("ارفع صورة JPG أو PNG أو WebP فقط."));
    cb(null, true);
  }
});
async function sendAdminEmail(subject, text) {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS || !process.env.MAIL_FROM) {
    console.warn("Email skipped: SMTP is not configured.", subject);
    return false;
  }
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE).toLowerCase() === "true",
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
  await transporter.sendMail({ from: process.env.MAIL_FROM, to: process.env.ADMIN_NOTIFICATION_EMAIL || adminEmail, subject, text });
  return true;
}
function audit(adminId, action, details) {
  db.prepare("INSERT INTO audit_logs(admin_id,action,details) VALUES(?,?,?)").run(adminId || null, action, details || "");
}
app.use("/api", csrfCheck);

app.get("/api/config", (_req, res) => {
  res.json({ walletNumber: process.env.WALLET_NUMBER || "01099183732", email: process.env.ADMIN_NOTIFICATION_EMAIL || adminEmail });
});
app.get("/api/me", (req, res) => res.json({ user: cleanUser(req.session.user) }));
app.post("/api/register", authLimiter, async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (name.length < 2 || name.length > 80) return res.status(400).json({ error: "اكتب اسمًا صحيحًا." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "البريد الإلكتروني غير صحيح." });
  if (password.length < 10) return res.status(400).json({ error: "كلمة المرور يجب أن تكون 10 أحرف على الأقل." });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name, email, hash);
    const user = db.prepare("SELECT id,name,email,role FROM users WHERE id=?").get(result.lastInsertRowid);
    req.session.user = user;
    sendAdminEmail("WAEL VIEWS: تسجيل مستخدم جديد", `اسم المستخدم: ${name}\nالبريد: ${email}\nوقت التسجيل: ${new Date().toISOString()}`).catch(e => console.error("Email error:", e.message));
    res.json({ user: cleanUser(user) });
  } catch (e) {
    if (String(e.code).includes("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "هذا البريد مسجل بالفعل." });
    console.error(e); res.status(500).json({ error: "تعذر إنشاء الحساب." });
  }
});
app.post("/api/login", authLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "البريد أو كلمة المرور غير صحيحة." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "تعذر بدء الجلسة." });
    req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
    res.json({ user: cleanUser(req.session.user) });
  });
});
app.post("/api/logout", requireAuth, (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get("/api/services", (_req, res) => {
  res.json(db.prepare("SELECT id,name,platform,description,price FROM services WHERE active=1 ORDER BY id").all());
});
app.post("/api/orders", requireAuth, (req, res) => {
  const serviceId = Number(req.body.serviceId);
  const targetUrl = String(req.body.targetUrl || "").trim();
  const service = db.prepare("SELECT * FROM services WHERE id=? AND active=1").get(serviceId);
  if (!service) return res.status(400).json({ error: "الخدمة غير متاحة." });
  if (targetUrl.length > 500 || !/^https:\/\/\S+/i.test(targetUrl)) return res.status(400).json({ error: "اكتب رابطًا صحيحًا يبدأ بـ https://." });
  const reference = "WV-" + crypto.randomBytes(5).toString("hex").toUpperCase();
  const result = db.prepare("INSERT INTO orders(reference,user_id,service_id,target_url,amount) VALUES(?,?,?,?,?)")
    .run(reference, req.session.user.id, service.id, targetUrl, service.price);
  const order = db.prepare("SELECT * FROM orders WHERE id=?").get(result.lastInsertRowid);
  sendAdminEmail("WAEL VIEWS: طلب جديد " + reference,
    `رقم الطلب: ${reference}\nالعميل: ${req.session.user.name} (${req.session.user.email})\nالخدمة: ${service.name} - ${service.platform}\nالمبلغ: ${(service.price/100).toFixed(2)} EGP\nالرابط: ${targetUrl}`)
    .catch(e => console.error("Email error:", e.message));
  res.json({ order });
});
app.get("/api/orders", requireAuth, (req, res) => {
  const rows = req.session.user.role === "admin"
    ? db.prepare(`SELECT o.*,u.name AS customer_name,u.email AS customer_email,s.name AS service_name,s.platform FROM orders o JOIN users u ON u.id=o.user_id JOIN services s ON s.id=o.service_id ORDER BY o.id DESC`).all()
    : db.prepare(`SELECT o.*,s.name AS service_name,s.platform FROM orders o JOIN services s ON s.id=o.service_id WHERE o.user_id=? ORDER BY o.id DESC`).all(req.session.user.id);
  res.json({ orders: rows });
});
app.post("/api/orders/:id/payment", requireAuth, (req, res) => {
  const order = db.prepare("SELECT * FROM orders WHERE id=?").get(Number(req.params.id));
  if (!order || (order.user_id !== req.session.user.id && req.session.user.role !== "admin")) return res.status(404).json({ error: "الطلب غير موجود." });
  if (order.payment_status === "verified") return res.status(400).json({ error: "تم تأكيد دفع هذا الطلب بالفعل." });
  upload.single("receipt")(req, res, async err => {
    if (err) return res.status(400).json({ error: err.message || "تعذر رفع الصورة." });
    if (!req.file) return res.status(400).json({ error: "ارفع صورة إيصال التحويل." });
    const method = String(req.body.method || "wallet");
    const sender = String(req.body.senderIdentifier || "").trim();
    const transferRef = String(req.body.transferReference || "").trim().slice(0, 120);
    const notes = String(req.body.notes || "").trim().slice(0, 500);
    if (!["wallet", "bank"].includes(method) || sender.length < 4 || sender.length > 80) {
      fs.unlink(req.file.path, () => {});
      return res.status(400).json({ error: "راجع طريقة الدفع ورقم المحوّل." });
    }
    // Inspect image signatures rather than trusting only the browser-provided MIME type.
    const fd = fs.openSync(req.file.path, "r");
    const sig = Buffer.alloc(12); fs.readSync(fd, sig, 0, 12, 0); fs.closeSync(fd);
    const valid = (sig[0]===0xff && sig[1]===0xd8 && sig[2]===0xff) ||
      (sig.toString("hex",0,8)==="89504e470d0a1a0a") ||
      (sig.toString("ascii",0,4)==="RIFF" && sig.toString("ascii",8,12)==="WEBP");
    if (!valid) { fs.unlink(req.file.path, () => {}); return res.status(400).json({ error: "محتوى الملف ليس صورة مدعومة." }); }
    try {
      const info = db.prepare("INSERT INTO payments(order_id,user_id,method,sender_identifier,transfer_reference,notes,receipt_filename) VALUES(?,?,?,?,?,?,?)")
        .run(order.id, req.session.user.id, method, sender, transferRef, notes, req.file.filename);
      db.prepare("UPDATE orders SET payment_status='submitted',status='payment_review' WHERE id=?").run(order.id);
      const paymentId = info.lastInsertRowid;
      sendAdminEmail("WAEL VIEWS: إيصال دفع جديد " + order.reference,
        `رقم الطلب: ${order.reference}\nرقم الدفع: ${paymentId}\nالعميل: ${req.session.user.name} (${req.session.user.email})\nالمبلغ: ${(order.amount/100).toFixed(2)} EGP\nطريقة الدفع: ${method}\nرقم المحوّل المُدخل: ${sender}\nمرجع التحويل: ${transferRef || "غير مقدم"}\nملاحظة: ${notes || "لا توجد"}\nراجع الإيصال من لوحة الإدارة بعد تسجيل الدخول.`)
        .catch(e => console.error("Email error:", e.message));
      res.json({ ok: true, message: "تم استلام الإيصال للمراجعة. لم يتم تأكيد الدفع تلقائيًا." });
    } catch (e) {
      fs.unlink(req.file.path, () => {}); console.error(e);
      res.status(500).json({ error: "تعذر حفظ بيانات الدفع." });
    }
  });
});
app.get("/api/admin/payments", requireAdmin, (_req, res) => {
  const rows = db.prepare(`SELECT p.*,o.reference,o.amount,o.currency,u.name AS customer_name,u.email AS customer_email
    FROM payments p JOIN orders o ON o.id=p.order_id JOIN users u ON u.id=p.user_id ORDER BY p.id DESC`).all();
  res.json({ payments: rows.map(p => ({ ...p, receiptUrl: "/api/admin/payments/" + p.id + "/receipt" })) });
});
app.get("/api/admin/payments/:id/receipt", requireAdmin, (req, res) => {
  const p = db.prepare("SELECT receipt_filename FROM payments WHERE id=?").get(Number(req.params.id));
  if (!p) return res.status(404).send("Not found");
  const file = path.join(PRIVATE_DIR, path.basename(p.receipt_filename));
  if (!fs.existsSync(file)) return res.status(404).send("Receipt not found");
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(file);
});
app.post("/api/admin/payments/:id/review", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const status = String(req.body.status || "");
  const note = String(req.body.note || "").trim().slice(0, 500);
  if (!["verified", "rejected"].includes(status)) return res.status(400).json({ error: "حالة غير صالحة." });
  const payment = db.prepare("SELECT * FROM payments WHERE id=?").get(id);
  if (!payment) return res.status(404).json({ error: "عملية الدفع غير موجودة." });
  const tx = db.transaction(() => {
    db.prepare("UPDATE payments SET status=?,review_note=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?")
      .run(status, note, req.session.user.id, id);
    db.prepare("UPDATE orders SET payment_status=?,status=? WHERE id=?")
      .run(status, status === "verified" ? "paid_awaiting_fulfillment" : "payment_rejected", payment.order_id);
    audit(req.session.user.id, "payment_" + status, "payment_id=" + id + "; order_id=" + payment.order_id);
  });
  tx();
  res.json({ ok: true });
});
app.get("/api/admin/summary", requireAdmin, (_req, res) => {
  res.json({
    users: db.prepare("SELECT COUNT(*) n FROM users WHERE role='customer'").get().n,
    orders: db.prepare("SELECT COUNT(*) n FROM orders").get().n,
    pendingPayments: db.prepare("SELECT COUNT(*) n FROM payments WHERE status IN ('submitted','under_review')").get().n,
    recentLogs: db.prepare("SELECT action,details,created_at FROM audit_logs ORDER BY id DESC LIMIT 30").all()
  });
});
app.patch("/api/admin/services/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const price = Number(req.body.price);
  const active = req.body.active ? 1 : 0;
  if (!Number.isInteger(price) || price < 0 || price > 100000000) return res.status(400).json({ error: "السعر غير صحيح." });
  const result = db.prepare("UPDATE services SET price=?,active=? WHERE id=?").run(price, active, id);
  if (!result.changes) return res.status(404).json({ error: "الخدمة غير موجودة." });
  audit(req.session.user.id, "service_updated", "service_id=" + id);
  res.json({ ok: true });
});
app.post("/api/admin/test-email", requireAdmin, async (_req, res) => {
  try {
    const sent = await sendAdminEmail("WAEL VIEWS: اختبار البريد", "إذا وصلتك هذه الرسالة، فإعداد SMTP يعمل.");
    if (!sent) return res.status(400).json({ error: "إعدادات SMTP غير مكتملة. أكملها في ملف .env ثم أعد التشغيل." });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: "فشل إرسال البريد: " + e.message }); }
});

app.use(express.static(path.join(ROOT, "public")));
app.get("*", (_req, res) => res.sendFile(path.join(ROOT, "public", "index.html")));
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "حدث خطأ غير متوقع. راجع سجل السيرفر." });
});
app.listen(PORT, () => console.log(`WAEL VIEWS running at http://localhost:${PORT}`));
