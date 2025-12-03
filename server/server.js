const express = require("express");
const { z } = require("zod");
const validator = require("validator");
const crypto = require("crypto");
//const https = require("node:https");
const cheerio = require("cheerio");
const path = require("path");
const cors = require("cors");
const winston = require("winston");
const axios = require("axios");
const dns = require("dns").promises;
const { body, validationResult } = require("express-validator");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
require("dotenv").config();
const jwt = require("jsonwebtoken");

mongoose
  .connect("mongodb://localhost:27017/DIplomska")
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Failed to connect to MongoDB", err));

const app = express();
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use("/images", express.static(path.join(__dirname, "images")));
app.set("trust proxy", 1);
const port = 3000;
const bodyParser = require("body-parser");
const { v4: uuidv4 } = require("uuid");

const booleanTextSchema = z.object({
  value: z.boolean().nullable(),
  text: z.string(),
});

const emailValidationResponseSchema = z.object({
  email: z.string().email(),
  autocorrect: z.string(),
  deliverability: z.enum(["DELIVERABLE", "UNDELIVERABLE", "RISKY", "UNKNOWN"]),
  quality_score: z.string().regex(/^\d\.\d{2}$/), // npr. "0.60"
  is_valid_format: booleanTextSchema,
  is_free_email: booleanTextSchema,
  is_disposable_email: booleanTextSchema,
  is_role_email: booleanTextSchema,
  is_catchall_email: booleanTextSchema,
  is_mx_found: booleanTextSchema,
  is_smtp_valid: booleanTextSchema,
});

//Sheme podatkov na bazi
const userSchema = new mongoose.Schema({
  uuid: { type: String, required: true, unique: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phoneNumber: { type: String, default: "" },
  gender: { type: String, default: null },
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user",
  },
});
const messageSchema = new mongoose.Schema({
  authorId: { type: String, required: true },
  authorEmail: { type: String, required: true },
  authorName: { type: String, required: true },
  timestamp: { type: String, required: true },
  content: { type: String, required: true },
});
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: "logs/error.log", level: "warn" }),
  ],
});
// Rate limiters have been removed

app.use(express.json({ limit: "100kb" }));

const User = mongoose.model("User", userSchema);
const Message = mongoose.model("Message", messageSchema);

function getGravatarUrl(email, size = 200) {
  const trimmedEmail = email.trim().toLowerCase();
  const hash = crypto.createHash("md5").update(trimmedEmail).digest("hex");
  return `https://www.gravatar.com/avatar/${hash}?s=${size}&d=retro`;
}

function checkAuthorizationHeader(req) {
  const authorizationHeader = req.headers.authorization;
  return authorizationHeader;
}

//Funkcija za generiranje zetonov
function generateToken(user) {
  return jwt.sign(
    {
      uuid: user.uuid,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN }
  );
}

//Funkcije za preverjanje zetonov
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    logger.warn("Unauthorized access attempt - missing token", {
      path: req.path,
      ip: req.ip,
      timestamp: new Date().toISOString(),
    });
    return res.status(401).json({ message: "Authorization token required" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

const permissions = {
  user: [
    "GET:/userInfo",
    "PUT:/userInfo",
    "GET:/messages",
    "POST:/postMessage",
  ],
  admin: [
    "GET:/allUsers",
    "DELETE:/usersDelete/:userId",
    "GET:/messages",
    "GET:/userInfo",
    "PUT:/userInfo",
    "POST:/postMessage",
  ],
};

function hasPermission(role, method, path) {
  const permission = `${method}:${path}`;
  if (method === "DELETE" && path.startsWith("/usersDelete/")) {
    return permissions[role]?.includes("DELETE:/usersDelete/:userId");
  }

  return permissions[role]?.includes(permission);
}

function checkPermissions(role) {
  return (req, res, next) => {
    if (hasPermission(role, req.method, req.path)) {
      next();
    } else {
      logger.warn("Unauthorized access attempt - missing token", {
        path: req.path,
        ip: req.ip,
        timestamp: new Date().toISOString(),
      });
      console.log("failed change!");
      return res.status(403).json({ message: "Access denied" });
    }
  };
}

app.use(bodyParser.json());

//https://datatracker.ietf.org/doc/html/rfc1918
function isPrivateIP(ip) {
  return (
    ip === "127.0.0.1" || // localhost
    ip === "::1" || // IPv6 localhost
    ip === "169.254.169.254" ||
    ip.startsWith("10.") ||
    (ip.startsWith("172.") &&
      parseInt(ip.split(".")[1]) >= 16 &&
      parseInt(ip.split(".")[1]) <= 31) ||
    ip.startsWith("192.168.") ||
    ip.startsWith("169.254.")
  );
}

async function resolveAllIPs(targetUrl) {
  console.log("resolveAllIPs called with:", targetUrl);
  if (!targetUrl) return [];
  try {
    const normalizedUrl = targetUrl.includes("://")
      ? targetUrl
      : `http://${targetUrl}`;
    const parsedUrl = new URL(normalizedUrl);
    const allowedSchemes = ["http:", "https:"];
    if (!allowedSchemes.includes(parsedUrl.protocol)) {
      throw new Error("Unsupported URL scheme");
    }
    const hostname = parsedUrl.hostname;
    const addresses = await dns.lookup(hostname, { all: true });
    return addresses.map((a) => a.address);
  } catch (err) {
    console.error("DNS resolution failed:", err);
    return [];
  }
}

app.get("/verifyToken", verifyToken, (req, res) => {
  res.status(200).json({ message: "Token valid", user: req.user });
});

//Pidobivanje podatkov za prikaz osebnega profila
app.get(
  "/userInfo",
  verifyToken,
  (req, res, next) => {
    const role = req.user?.role;
    return checkPermissions(role)(req, res, next);
  },
  async (req, res) => {
    const userUuid = req.user.uuid;

    if (!userUuid) {
      return res.status(400).send("User UUID required");
    }

    try {
      const user = await User.findOne({ uuid: userUuid });
      if (user) {
        const gravatarUrl = getGravatarUrl(user.email);
        return res.status(200).json({
          success: true,
          message: "User founded",
          user: {
            ...user.toObject(),
            gravatar: gravatarUrl,
          },
        });
      } else {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }
    } catch (err) {
      console.error("Error retrieving user:", err);
      return res.status(500).json({
        success: false,
        message: "Internal server error",
      });
    }
  }
);

app.put(
  "/userInfo",
  [
    body("firstName").isString().trim().escape(),
    body("lastName").isString().trim().escape(),
    body("gender").isIn(["male", "female", "other"]).optional(),
    body("password").optional().isLength({ min: 6 }),
  ],
  verifyToken,
  (req, res, next) => {
    const role = req.user?.role;
    return checkPermissions(role)(req, res, next);
  },
  async (req, res) => {
    const updatedProfle = req.body;
    console.log(JSON.stringify(updatedProfle) + " body request");

    try {
      const user = await User.findOne({ uuid: req.user.uuid });
      if (!user) {
        logger.warn(
          "User not found: wrong credentials sended through the cookie",
          {
            url: url,
            ip: req.ip,
            resolvedIPs: ips,
            timestamp: new Date().toISOString(),
          }
        );
        return res.status(404).json({ message: "User not found" });
      }

      const allowedUpdates = ["firstName", "lastName", "gender", "password"];

      for (const key of Object.keys(updatedProfle)) {
        if (allowedUpdates.includes(key)) {
          if (key === "password") {
            if (updatedProfle[key]) {
              console.log("Hashing password...");
              try {
                const hashedPassword = await bcrypt.hash(
                  updatedProfle[key],
                  10
                );
                user.password = hashedPassword;
              } catch (err) {
                return res.status(500).json({ message: "Password hash error" });
              }
            }
          } else {
            user[key] = updatedProfle[key];
          }
        }
      }

      await user.save();
      res.json({ message: `Profile ${user._id} updated successfully!`, user });
    } catch (error) {
      console.error("Error updating profile:", error);
      res
        .status(500)
        .json({ message: "Failed to update profile", error: error.message });
    }
  }
);

//Končna točka namenjena administratorju
app.delete(
  "/usersDelete/:id",
  verifyToken,
  (req, res, next) => {
    const role = req.user?.role;
    return checkPermissions(role)(req, res, next);
  },
  async (req, res) => {
    const userId = req.params.id;
    if (!userId) {
      logger.warn("ID missing for deleting users", {
        url: url,
        ip: req.ip,
        resolvedIPs: ips,
        timestamp: new Date().toISOString(),
      });
      return res
        .status(400)
        .json({ success: false, message: "Manjka ID uporabnika" });
    }
    try {
      const deletedUser = await User.findOneAndDelete({ uuid: userId });

      if (!deletedUser) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }

      res.json({ success: true, message: `Uporabnik ${userId} izbrisan` });
    } catch (err) {
      console.error("Napaka pri brisanju:", err);
      res
        .status(500)
        .json({ success: false, message: "Napaka pri brisanju uporabnika" });
    }
  }
);

//Pridobitev uporabnikov iz baze
app.get(
  "/allUsers",
  verifyToken,
  (req, res, next) => {
    const role = req.user?.role;
    return checkPermissions(role)(req, res, next);
  },
  async (req, res) => {
    try {
      console.log("AllUsers endpoint called");
      console.log(req.headers.authorization);

      const users = await User.find();
      if (users.length > 0) {
        res.json({
          success: true,
          message: "All users retrieved successfully",
          token: req.headers.authorization?.split(" ")[1],
          users,
        });
      } else {
        return res.status(404).send("No users found");
      }
    } catch (error) {
      console.error("Error fetching users:", error);
      return res.status(500).send("Internal server error");
    }
  }
);
//1. metoda klicana
app.get(
  "/user",
  verifyToken,
  (req, res, next) => {
    const role = req.user?.role;
    return checkPermissions(role)(req, res, next);
  },
  async (req, res) => {
    console.log("GET /user called");

    const userUuid = req.query.uuid;

    if (!userUuid) {
      logger.warn("Missing user ID in the request", {
        url: url,
        ip: req.ip,
        resolvedIPs: ips,
        timestamp: new Date().toISOString(),
      });
      return res.status(400).send("User UUID required");
    }

    try {
      const user = await User.findOne({ uuid: userUuid });

      if (user) {
        console.log("NAJDENI UPORABNIK");
        return res.json(user);
      } else {
        logger.warn("Triying to acces data of a non-existing user.", {
          url: url,
          ip: req.ip,
          resolvedIPs: ips,
          timestamp: new Date().toISOString(),
        });
        return res.status(404).send("User not found");
      }
    } catch (err) {
      console.error("Error retrieving user:", err);
      return res.status(500).send("Error retrieving user from the database"); // Catch any other errors
    }
  }
);

//Dodajanje sporocil
app.post(
  "/postMessage",
  verifyToken,
  (req, res, next) => {
    const role = req.user?.role;
    return checkPermissions(role)(req, res, next);
  },
  async (req, res) => {
    console.log("postMessage /postMessage called");
    console.log(req.body);

    const { authorId, authorEmail, authorName, timestamp, content } = req.body;

    if (!authorName || !timestamp || !content) {
      logger.warn("Invalid message format", {
        url: url,
        ip: req.ip,
        resolvedIPs: ips,
        timestamp: new Date().toISOString(),
      });
      return res.status(400).json({ error: "Missing required fields" });
    }

    const newMessage = new Message({
      authorId,
      authorEmail,
      authorName,
      timestamp,
      content,
    });

    try {
      await newMessage.save();
      res.status(201).json(newMessage);
    } catch (error) {
      console.error("Error saving message:", error);
      res.status(500).json({ error: "Failed to save message" });
    }
  }
);

app.post("/userLogin", async (req, res) => {
  const email = req.body.emailValue;
  const pswd = req.body.psw;

  if (!email || !pswd) {
    return res.status(400).send("Email and password are required");
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      logger.warn(`User with the provided email doesn't exist.`, {
        email,
        ip: req.ip,
        time: new Date().toISOString(),
      });
      return res.status(404).send("Invalid credentials.");
    }

    const isMatch = await bcrypt.compare(pswd, user.password);
    if (!isMatch) {
      logger.warn(`Wrong password for the following address: ${email}`, {
        email,
        ip: req.ip,
        time: new Date().toISOString(),
      });
      return res.status(401).send("Invalid credentials.");
    }

    const token = generateToken(user);
    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        _id: user.uuid,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("Error retrieving user:", err);
    res.status(500).send("Error retrieving user from the database");
  }
});

app.get(
  "/messages",
  verifyToken,
  (req, res, next) => {
    const role = req.user?.role;
    return checkPermissions(role)(req, res, next);
  },
  async (req, res) => {
    console.log("GET /messages called");
    const idFromAuthorization = checkAuthorizationHeader(req);

    if (idFromAuthorization) {
      try {
        const messages = await Message.find();
        if (messages.length > 0) {
          console.log();
          return res.json(messages);
        } else {
          return res.status(404).send("No messages found");
        }
      } catch (error) {
        console.error("Error fetching messages:", error);
        return res.status(500).send("Internal server error");
      }
    }

    res.status(401).send("Authorization required");
  }
);

app.post("/userRegistracija", async (req, res) => {
  const url = req.protocol + "://" + req.get("host") + req.originalUrl;
  const ips = req.ips && req.ips.length > 0 ? req.ips : [req.ip];
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.psw, salt);

  try {
    if (!validator.isEmail(req.body.emailValue)) {
      logger.warn("Email adress sended for registration not valid.", {
        url: url,
        ip: req.ip,
        resolvedIPs: ips,
        timestamp: new Date().toISOString(),
      });
      return res.status(400).send("Credentials are not valid.");
    }
    const apiKey = process.env.ABSTRACT_API_KEY;
    console.log("API key:", apiKey);
    const responseValidEmail = await axios.get(
      `https://emailvalidation.abstractapi.com/v1/?api_key=${apiKey}&email=${req.body.emailValue}`,
      { timeout: 5000 }
    );
    if (responseValidEmail.status !== 200) {
      logger.warn("Not valid format email passed", {
        url: url,
        ip: req.ip,
        resolvedIPs: ips,
        timestamp: new Date().toISOString(),
      });

      console.error(
        "Email validation API returned an error:",
        responseValidEmail.status
      );
      return res
        .status(400)
        .json({ success: false, message: "Credentials not valid." });
    }

    const result = emailValidationResponseSchema.safeParse(
      responseValidEmail.data
    );
    const parsedData = result.data;
    if (!result.success) {
      console.error("Napaka pri validaciji:", result.error.format());
      logger.warn("Invalid request.", {
        url: url,
        ip: req.ip,
        resolvedIPs: ips,
        timestamp: new Date().toISOString(),
      });
      return res.status(404).send("Invalid request.");
    }
    const validEmail = parsedData.email;
    if (req.body.emailValue !== validEmail) {
      logger.warn("Invalid request.", {
        url: url,
        ip: req.ip,
        resolvedIPs: ips,
        timestamp: new Date().toISOString(),
      });
      return res.status(400).json({
        success: false,
        message: "Validation failed.",
      });
    }
    if (
      parsedData.deliverability !== "DELIVERABLE" ||
      parsedData.is_disposable_email?.value === true ||
      parsedData.is_role_email?.value === true ||
      parsedData.is_valid_format?.value !== true ||
      parsedData.is_mx_found?.value !== true ||
      parsedData.is_smtp_valid?.value !== true
    ) {
      logger.warn("Invalid credentials.", {
        url: url,
        ip: req.ip,
        resolvedIPs: ips,
        timestamp: new Date().toISOString(),
      });
      //console.log("Invalid email address");
      return res
        .status(400)
        .json({ success: false, message: "Email already in use." });
    }
    const existingUser = await User.findOne({ email: validEmail });
    if (existingUser) {
      logger.warn("User tried to use an email address that already exists.", {
        url: url,
        ip: req.ip,
        resolvedIPs: ips,
        timestamp: new Date().toISOString(),
      });
      return res.status(409).send("Invalid credentials.");
    }

    const newUser = new User({
      uuid: uuidv4(),
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      email: validEmail,
      password: hashedPassword,
      phoneNumber: req.body.rojstniDan,
      gender: req.body.genderValue,
    });
    await newUser.save();
    return res.json({
      success: true,
      message: "Registration successful",
      newUser,
    });
  } catch (err) {
    if (err.code === "ECONNABORTED") {
      console.error("Email validation API request timed out");
      return res
        .status(504)
        .json({ success: false, message: "Email validation timed out" });
    }
    console.error("Error saving user:", err);
    return res
      .status(500)
      .send("Internal server error. Please try again later.");
  }
});
app.get("/", (req, res) => {
  res.send("Hello, world!");
});

app.listen(port, async () => {
  console.log(`Lokalni strežnik teče na http://localhost:${port}`);
});
