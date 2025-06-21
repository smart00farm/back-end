// ====== server.js (Production-grade, Modular, Secure, Documented) ======
require("dotenv").config();
const express      = require("express");
const mongoose     = require("mongoose");
const cors         = require("cors");
const helmet       = require("helmet");
const morgan       = require("morgan");
const rateLimit    = require("express-rate-limit");
const compression  = require("compression");
const swaggerUi    = require("swagger-ui-express");
const fs           = require("fs");
const path         = require("path");
const nodemailer   = require("nodemailer");
const axios        = require("axios");
const jwt          = require("jsonwebtoken");
const Joi          = require("joi");
const bcrypt       = require("bcryptjs");

// ========== Import Routers ==========
const sensorRoutes    = require("./routes/sensors");
const imageRoutes     = require("./routes/images");
const aiRoutes        = require("./routes/ai");
const controlRoutes   = require("./routes/control");
const authMiddleware  = require("./utils/authMiddleware");
const roleMiddleware  = require("./utils/roleMiddleware");
const Logs            = require("./models/Logs");
const SensorData      = require("./models/SensorData");
const ImageData       = require("./models/ImageData");
const User            = require("./models/User");
const AIResult        = require("./models/AIResult");
const swaggerDocument = require("./swagger.json");

// ========== App Init ==========
const app = express();

// ========== Secure Rate Limiting ==========
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  keyGenerator: (req) => req.headers["esp-id"] || req.ip,
  message: { status: "fail", error: "Too many requests. Please slow down." }
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  message: { status: "fail", error: "Too many auth attempts. Try later." }
});
const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { status: "fail", error: "Too many uploads. Please slow down." }
});

// ========== Device API Key Middleware ==========
const validDeviceKeys = (process.env.DEVICE_KEYS || "").split(",");
function deviceApiKeyMiddleware(req, res, next) {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || !validDeviceKeys.includes(apiKey)) {
    return res.status(401).json({ status: "fail", error: "Invalid device API key" });
  }
  next();
}

// ========== HTTPS (Production Proxy) ==========
if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
  // Uncomment to enforce HTTPS behind proxy:
  // app.use((req, res, next) => {
  //   if (req.headers['x-forwarded-proto'] !== 'https') return res.redirect('https://' + req.headers.host + req.url);
  //   next();
  // });
}

// ========== Middleware Setup ==========
app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(",") || "*" }));
app.use(limiter);
app.use(compression());
app.use(express.json({ limit: "16mb" }));
app.use(morgan("dev"));
app.use("/uploads", express.static(path.join(__dirname, "uploads"))); // Static for images

// ========== MongoDB Connection ==========
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.connection.on("connected", () => console.log("✅ MongoDB connected"));
mongoose.connection.on("error", (err) => {
  console.error("❌ MongoDB error:", err);
  sendSystemAlert("MongoDB Error: " + err.message);
});

// ========== Alerts (Email/Telegram) ==========
const EMAIL_ENABLED = process.env.EMAIL_ENABLED === "true";
const TELEGRAM_ENABLED = process.env.TELEGRAM_ENABLED === "true";
const transporter = EMAIL_ENABLED ? nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: 465,
  secure: true,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
}) : null;
async function sendSystemAlert(msg) {
  if (TELEGRAM_ENABLED && process.env.TELEGRAM_TOKEN && process.env.TELEGRAM_CHAT_ID) {
    await axios.get(https://api.telegram.org/bot${process.env.TELEGRAM_TOKEN}/sendMessage, {
      params: { chat_id: process.env.TELEGRAM_CHAT_ID, text: 🚨 [ALERT] ${msg} }
    }).catch(() => {});
  }
  if (EMAIL_ENABLED && transporter) {
    await transporter.sendMail({
      from: process.env.SMTP_USER,
      to: process.env.ADMIN_EMAIL,
      subject: "System Alert",
      text: msg
    }).catch(() => {});
  }
  await Logs.create({ type: "alert", message: msg });
}

// ========== Auth Routes ==========
app.post("/api/auth/signup", authLimiter, async (req, res) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required(),
    role: Joi.string().valid("admin", "user", "viewer").default("user")
  });
  const { error, value } = schema.validate(req.body);
  if (error) return res.status(400).json({ status: "fail", error: error.details[0].message });

  try {
    if (await User.findOne({ email: value.email })) {
      return res.status(409).json({ status: "fail", error: "User already exists" });
    }
    const hashedPassword = await bcrypt.hash(value.password, 12);
    await new User({ email: value.email, password: hashedPassword, role: value.role }).save();
    await Logs.create({ type: "user", message: "User signed up", esp_id: value.email });
    res.status(201).json({ status: "success", message: "User created" });
  } catch (err) {
    await Logs.create({ type: "error", message: err.message });
    sendSystemAlert("Signup Error: " + err.message);
    res.status(500).json({ status: "fail", error: err.message });
  }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const schema = Joi.object({
    email: Joi.string().required(),
    password: Joi.string().required()
  });
  const { error, value } = schema.validate(req.body);
  if (error) return res.status(400).json({ status: "fail", error: error.details[0].message });

  try {
    const user = await User.findOne({ email: value.email });
    if (!user) return res.status(401).json({ status: "fail", error: "User not found" });
    const isMatch = await bcrypt.compare(value.password, user.password);
    if (!isMatch) return res.status(401).json({ status: "fail", error: "Invalid password" });
    // Optional: Add OTP/2FA here
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "7d" });
    await Logs.create({ type: "user", message: "User login", esp_id: value.email });
    res.json({ status: "success", token });
  } catch (err) {
    await Logs.create({ type: "error", message: err.message });
    sendSystemAlert("Login Error: " + err.message);
    res.status(500).json({ status: "fail", error: err.message });
  }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) return res.status(404).json({ status: "fail", error: "User not found" });
    res.json({ status: "success", data: user });
  } catch (err) {
    res.status(500).json({ status: "fail", error: err.message });
  }
});

// ========== Device (ESP32) Upload APIs ==========
app.post("/api/images/upload", deviceApiKeyMiddleware, uploadLimiter, async (req, res) => {
  try {
    if (!req.headers['content-type'] || !req.headers['content-type'].includes('image/jpeg')) {
      return res.status(415).json({ status: "fail", error: "Invalid file type. Only JPEG allowed." });
    }
    if (parseInt(req.headers['content-length'] || 0) > 5 * 1024 * 1024) {
      return res.status(413).json({ status: "fail", error: "Image too large. Max 5MB allowed." });
    }
    // رفع وحفظ الصورة
    const imgName = Date.now() + ".jpg";
    const imgPath = path.join(__dirname, "uploads", imgName);
    const imgBuffer = req.body instanceof Buffer ? req.body : Buffer.from([]);
    fs.writeFileSync(imgPath, imgBuffer);

    // image analysis / compression with sharp can be added here

    const imgUrl = process.env.BASE_URL + "/uploads/" + imgName;
    const image = new ImageData({ url: imgUrl });
    await image.save();
    res.status(201).json({ status: "success", imgUrl });
  } catch (err) {
    await Logs.create({ type: "error", message: err.message });
    sendSystemAlert("Image Upload Error: " + err.message);
    res.status(500).json({ status: "fail", error: err.message });
  }
});

app.post("/api/sensors/upload", deviceApiKeyMiddleware, async (req, res) => {
  try {
    const data = new SensorData(req.body);
    await data.save();
    res.status(201).json({ status: "success" });
  } catch (err) {
    await Logs.create({ type: "error", message: err.message });
    sendSystemAlert("Sensor Upload Error: " + err.message);
    res.status(500).json({ status: "fail", error: err.message });
  }
});

// ========== Dashboard Stats ==========
app.get("/api/dashboard/stats", authMiddleware, roleMiddleware(["admin"]), async (req, res) => {
  try {
    const [sensorCount, imageCount, userCount, alertsCount] = await Promise.all([
      SensorData.countDocuments(),
      ImageData.countDocuments(),
      User.countDocuments(),
      Logs.countDocuments({ type: "alert" })
    ]);
    res.json({
      status: "success",
      data: {
        totalSensors: sensorCount,
        totalImages: imageCount,
        totalUsers: userCount,
        totalAlerts: alertsCount
      }
    });
  } catch (err) {
    res.status(500).json({ status: "fail", error: err.message });
  }
});

app.get("/api/logs/alerts", authMiddleware, roleMiddleware(["admin"]), async (req, res) => {
  try {
    const alerts = await Logs.find({ type: "alert" }).sort({ timestamp: -1 }).limit(50);
    res.json({ status: "success", data: alerts });
  } catch (err) {
    res.status(500).json({ status: "fail", error: err.message });
  }
});

// ========== Modular Routes ==========
app.use("/api/images", authMiddleware, imageRoutes);
app.use("/api/ai",     authMiddleware, aiRoutes);
app.use("/api/sensors",authMiddleware, sensorRoutes);
app.use("/api/control",authMiddleware, roleMiddleware(["admin"]), controlRoutes);

// ========== Swagger Docs ==========
app.use("/api/docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// ========== Health & Metrics ==========
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

// ========== Catch-All 404 ==========
app.use((req, res) => {
  res.status(404).json({ status: "fail", error: "Route not found" });
});

// ========== Start Server ==========
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("🚀 Backend running on port " + PORT));