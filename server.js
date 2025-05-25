const express = require("express");
const app = express();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const nodemailer = require("nodemailer");
const cors = require('cors');``

const Admin = require("./models/Admin");
const Category = require("./models/Category");
const Post = require("./models/Post");
const Comment = require("./models/Comment");

require("dotenv").config();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname + "/../Frontend"));

// CORS Configuration
const allowedOrigins = [
  process.env.FRONTEND,
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS policy error: ${origin} is not allowed.`));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 3600, // Add this option to specify the maximum age of the CORS configuration
};

app.use(cors(corsOptions));

// Connect to MongoDB
mongoose
  .connect(process.env.DB_URL)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Authentication Middleware
const authenticate = async (req, res, next) => {
  const token = req.cookies.token;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await Admin.findById(decoded.adminId);
    // console.log(req.user)
    next();
  } catch (error) {
    res.status(401).json({ message: "Unauthorized" });
  }
};

// Verify Token Middleware
const verifyTokenMiddleware = async (req, res, next) => {
  const verificationToken = req.cookies.verificationToken;
  try {
    const decodedToken = jwt.verify(verificationToken, process.env.JWT_SECRET);
    if (decodedToken.purpose !== "resend-verification") {
      return res.status(401).json({ message: "Invalid token" });
    }
    req.adminId = decodedToken.adminId;
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token has expired" });
    } else if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ message: "Invalid token" });
    } else {
      throw error;
    }
  }
};

// Check User Permission
const checkPermission = (action) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({ message: "Please authenticate" });
      }
      const permissions = {
        admin: ["create", "view", "update", "delete", "search"],
        user: ["view", "search"],
      };
      if (
        !permissions[req.user.role] ||
        !permissions[req.user.role].includes(action)
      ) {
        return res.status(401).json({
          message: "You don't have the permission to perform this operation",
        });
      }
      next();
    } catch (error) {
      res.status(500).json({ message: "Error checking permission" });
    }
  };
};

// Send verification email
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});


// Rate limiting
const limiter = rateLimit({
  windowMs: 2 * 60 * 1000, // 2 minutes
  max: 8, // Limit each IP to 5 requests per windowMs
  handler: (request, response, next) => {
    response.status(429).json({
      message: "Too many requests, please try again later.",
    });
  },
});

// Validation Schemas
const registerSchema = Joi.object({
  name: Joi.string().required().trim().min(3).messages({
    "string.empty": "Name is required",
    "string.min": "Name must contain at least 3 characters",
    "any.required": "Name is required",
  }),
  email: Joi.string().email().required().trim().messages({
    "string.empty": "Email is required",
    "string.email": "Invalid email format",
    "any.required": "Email is required",
  }),
  password: Joi.string().required().trim().min(6).max(8).messages({
    "string.empty": "Password is required",
    "string.min": "Password must contain at least 6 characters",
    "string.max": "Password must not exceed 8 characters",
    "any.required": "Password is required",
  }),
  confirmPassword: Joi.any().valid(Joi.ref('password')).required().messages({
    'any.only': 'Passwords do not match',
  }),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required().trim().messages({
    "string.empty": "Email is required",
    "string.email": "Invalid email format",
    "any.required": "Email is required",
  }),
  password: Joi.string().required().trim().messages({
    "string.empty": "Password is required",
    "any.required": "Password is required",
  }),
});

const forgotPasswordSchema = Joi.object({
  email: Joi.string().email().required().trim().messages({
    "string.empty": "Email is required",
    "string.email": "Invalid email format",
    "any.required": "Email is required",
  }),
});

const resetPasswordSchema = Joi.object({
  password: Joi.string().required().trim().min(4).max(8).messages({
    "string.empty": "Password is required",
    "string.min": "Password must contain at least 4 characters",
    "string.max": "Password must not exceed 8 characters",
    "any.required": "Password is required",
  }),
});

const categorySchema = Joi.object({
  name: Joi.string().required().trim().messages({
    "string.empty": "Category name is required",
    "any.required": "Category name is required",
  }),
  description: Joi.string().allow("").optional().trim(),
});

const postSchema = Joi.object({
  primaryImage: Joi.string().required(),
  images: Joi.array().items(Joi.string()),
  title: Joi.string().required(),
  category: Joi.string().required(),
  content: Joi.string().required(),
  description: Joi.string().required(),
  tag: Joi.array().items(Joi.string().required()).min(1).required(),
  videos: Joi.array().items(Joi.string()),
});

const contactSchema = Joi.object({
  name: Joi.string().required().trim().min(3).messages({
    "string.empty": "Name is required",
    "string.min": "Name must contain at least 3 characters",
    "any.required": "Name is required",
  }),
  email: Joi.string().email().required().trim().messages({
    "string.empty": "Email is required",
    "string.email": "Invalid email format",
    "any.required": "Email is required",
  }),
  phone: Joi.string().required().trim().messages({
    "string.empty": "Phone number is required",
    "any.required": "Phone number is required",
  }),
  company: Joi.string().trim().allow('').optional(),
  service: Joi.string().required().trim().messages({
    "string.empty": "Service is required",
    "any.required": "Service is required",
  }),
  message: Joi.string().required().trim().min(10).messages({
    "string.empty": "Message is required",
    "string.min": "Message must contain at least 10 characters",
    "any.required": "Message is required",
  }),
});


// ADMIN AUTHENTICATION

// Admin Register End point - Connected
app.post("/api/admin-register", limiter, async (req, res) => {
  // Validation check
  try {
    await registerSchema.validateAsync(req.body);
  } catch (error) {
    return res.status(400).json({
      message: error.details[0].message,
    });
  }

  const { name, email, password } = req.body;

  console.log(req.body)

  // Name uniqueness check
  const existingName = await Admin.findOne({ name });
  if (existingName) {
    return res.status(400).json({
      message: "Name already taken",
    });
  }

  // Email uniqueness check
  const existingEmail = await Admin.findOne({ email });
  if (existingEmail) {
    return res.status(400).json({
      message: "Email already in use",
    });
  }

  // Password hashing
  const hash = await bcrypt.hash(password, 10);

  // Save admin info to database
  const admin = new Admin({
    name,
    email,
    password: hash,
    role: "admin",
    verified: false,
  });

  try {
    await admin.save();

    const verificationToken = jwt.sign(
      { adminId: admin._id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: admin.email,
      subject: "Verify your email",
      text: `Verify your email by clicking this link: ${process.env.FRONTEND}/admin/verify-email/${verificationToken}`,
    };

    transporter.sendMail(mailOptions, async (error, info) => {
      if (error) {
        console.log(error);
        admin.verificationFailed = true;
        await admin.save();
        res.status(500).json({
          message: "Error sending verification email. Please try again later.",
        });
      } else {
        console.log("Email sent: " + info.response);
        res.status(200).json({
          message: "Registration successful! Please check your email inbox to verify your account."
        });
      }
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Error saving admin details" });
  }
});

// Verify Email End point - Connected
app.get("/api/verify-email/:token", async (req, res) => {
  try {
    const token = req.params.token;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.adminId);
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }
    admin.verified = true;
    await admin.save();
    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    console.log(error.messageyy);
    res.status(400).json({ message: "Invalid or expired token" });
  }
});

// Admin Login End point - Connected
app.post("/api/admin-login", limiter, async (req, res) => {
  try {
    await loginSchema.validateAsync(req.body);
  } catch (error) {
    return res.status(400).json({
      message: error.details[0].message,
    });
  }

  const { email, password } = req.body;
  const admin = await Admin.findOne({ email });
  if (!admin) {
    return res.status(400).json({ message: "Invalid Email or Password" });
  }

  const isValidPassword = await bcrypt.compare(password, admin.password);
  if (!isValidPassword) {
    return res.status(400).json({ message: "Invalid Email or Password" });
  }

  if (!admin.verified) {
    const verificationToken = jwt.sign(
      {
        adminId: admin._id,
        email: admin.email,
        purpose: "resend-verification",
      },
      process.env.JWT_SECRET
    );
    res.cookie("verificationToken", verificationToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      expires: new Date(Date.now() + 3600000), // 1 hour
    });
    return res.status(400).json({ message: "Email not verified" });
  }

  const token = jwt.sign(
    { adminId: admin._id, role: admin.role },
    process.env.JWT_SECRET,
    {
      expiresIn: "1h",
    }
  );

  res.cookie("token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    expires: new Date(Date.now() + 3600000), // 1 hour
  });

  res.status(200).json({ message: "Login Successful" });
});

// Admin Logout End point - Connected
app.post("/api/admin-logout", authenticate, (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });
    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to log out" });
  }
});

// Forgot Password Endpoint - Connected
app.post("/forgot-password", async (req, res) => {
  try {
    await forgotPasswordSchema.validateAsync(req.body);
  } catch (error) {
    return res.status(400).json({
      message: error.details[0].message,
    });
  }

  try {
    const { email } = req.body;
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(400).json({ message: "Admin not found" });
    }

    const resetToken = jwt.sign(
      { adminId: admin._id },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    admin.resetToken = resetToken;
    admin.resetTokenExpiration = Date.now() + 3600000; // 1 hour
    await admin.save();

    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: admin.email,
      subject: "Password Reset",
      text: `Reset your password by clicking this link: http://localhost:3000/reset-password/${resetToken}`,
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        res.status(500).json({ message: "Error sending email" });
      } else {
        res.status(200).json({ message: "Password reset email sent" });
      }
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error processing request" });
  }
});

// Reset Password Endpoint - Connected
app.post("/reset-password/:token", async (req, res) => {
  try {
    await resetPasswordSchema.validateAsync(req.body);
  } catch (error) {
    return res.status(400).json({
      message: error.details[0].message,
    });
  }

  try {
    const token = req.params.token;
    const { password } = req.body;

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.adminId);
    if (!admin) {
      return res.status(400).json({ message: "Invalid token" });
    }

    if (admin.resetTokenExpiration < Date.now()) {
      return res.status(400).json({ message: "Token expired" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    admin.password = hashedPassword;
    admin.resetToken = undefined;
    admin.resetTokenExpiration = undefined;
    await admin.save();

    res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error resetting password" });
  }
});

// Resend Verification Endpoint - Connected
app.post("/resend-verification", verifyTokenMiddleware, async (req, res) => {
  try {
    const admin = await Admin.findById(req.adminId);
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }

    if (admin.verified) {
      return res.status(400).json({ message: "Email already verified" });
    }

    const verifyToken = jwt.sign(
      { adminId: admin._id },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: admin.email,
      subject: "Verify your email",
      text: `Verify your email by clicking this link: http://localhost:3000/verify-email/${verifyToken}`,
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      console.log("Email sent: " + info.response);
      res.status(200).json({ message: "Email Verification sent" });
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: "Error sending verification email" });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error processing request" });
  }
});


// Contact us send to mail
app.post('/api/send-email', limiter, async (req, res) => {
  // Validation check
  try {
    await contactSchema.validateAsync(req.body);
  } catch (error) {
    return res.status(400).json({
      message: error.details[0].message,
    });
  }

  const { name, email, phone, company, message, service } = req.body;
  console.log("req.body", req.body)
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: process.env.CONTACT_EMAIL,
    subject: `New Message From ${name}`,
    text: `Name: ${name}\nEmail: ${email}\nPhone: ${phone}\nCompany: ${company}\nService: ${service}\nMessage: ${message}`,
  };
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending email:', error);
      res.status(500).send('Error sending email');
    } else {
      res.send('Email sent successfully');
    }
  });
});


































































// ADMIN CRUD OPERATION

// Delete All Admins from Database End point - Tested
app.delete("/admins", async (req, res) => {
  try {
    await Admin.deleteMany({});
    res.status(200).json({ message: "All admins deleted successfully" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error deleting admins" });
  }
});

// Get All Admins from Database End point - Tested
app.get("/admins", async (req, res) => {
  try {
    const admins = await Admin.find().select("-password");
    res.status(200).json(admins);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error fetching admins" });
  }
});

// CATEGORY CRUD OPERATION

// Create Category (admin only) - Connected
app.post(
  "/category",
  authenticate,
  checkPermission("create"),
  async (req, res) => {
    try {
      await categorySchema.validateAsync(req.body);
    } catch (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { name, description } = req.body;

    // Check if category already exists
    const existingCategory = await Category.findOne({ name });
    if (existingCategory) {
      return res.status(400).json({ message: "Category already exists" });
    }

    try {
      const categoryData = { name };
      if (description !== undefined && description.trim() !== "") {
        categoryData.description = description;
      }
      const category = new Category(categoryData);
      await category.save();
      res.status(201).json({ message: "Category created successfully" });
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: "Error creating category" });
    }
  }
);

// Get Category (admin and user) - Connected
app.get("/category", async (req, res) => {
    try {
      const categories = await Category.find();
      res.status(200).json(categories);
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: "Error fetching categories" });
    }
  }
);

// Delete Category (admin only) - Connected
app.delete(
  "/category/:id",
  authenticate,
  checkPermission("delete"),
  async (req, res) => {
    try {
      const categoryId = req.params.id;
      const category = await Category.findByIdAndDelete(categoryId);
      if (!category) {
        return res.status(404).json({ message: "Category not found" });
      }
      res.status(200).json({ message: "Category deleted successfully" });
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: "Error deleting category" });
    }
  }
);

// Update Category (admin only) - Connected
app.put(
  "/category/:id",
  authenticate,
  checkPermission("update"),
  async (req, res) => {
    try {
      await categorySchema.validateAsync(req.body);
    } catch (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    try {
      const categoryId = req.params.id;
      const { name, description } = req.body;

      // Check if category name already exists
      const existingCategory = await Category.findOne({
        name,
        _id: { $ne: categoryId },
      });
      if (existingCategory) {
        return res
          .status(400)
          .json({ message: "Category name already exists" });
      }

      const updateData = { name };
      updateData.description =
        description.trim() === "" ? "No Description" : description;

      const category = await Category.findByIdAndUpdate(
        categoryId,
        updateData,
        { new: true }
      );
      if (!category) {
        return res.status(404).json({ message: "Category not found" });
      }
      res
        .status(200)
        .json({ message: "Category updated successfully", category });
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: "Error updating category" });
    }
  }
);

// POST CRUD OPERATION

// Create post (admin only) - Connected
app.post("/post", authenticate, checkPermission("create"), async (req, res) => {
  try {
    await postSchema.validateAsync(req.body);
  } catch (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    const categoryId = req.body.category;
    if (!mongoose.Types.ObjectId.isValid(categoryId)) {
      return res.status(400).json({ message: "Invalid category ID" });
    }

    const category = await Category.findById(categoryId);
    if (!category) {
      return res.status(400).json({ message: "Category not found" });
    }

    delete req.body.postedBy; // Delete postedBy field from request body
    const postData = new Post(req.body);
    await postData.save();
    res.status(201).json({ message: "Post created successfully" });
  } catch (error) {
    console.log(error);
    if (error.name === "ValidationError") {
      return res.status(400).json({ message: error.message });
    }
    res.status(500).json({ message: "Error creating post" });
  }
});

// View All Posts (admin and user) - Connected
app.get("/post", async (req, res) => {
  try {
    const posts = await Post.find().populate("category");
    res.status(200).json(posts);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error fetching posts" });
  }
});

// View Post by ID (admin and user) - Connected
app.get("/post/:id", async (req, res) => {
  try {
    const postId = req.params.id;
    if (!mongoose.Types.ObjectId.isValid(postId)) {
      return res.status(400).json({ message: "Invalid post ID" });
    }

    const postData = await Post.findById(postId).populate("category");
    if (!postData) {
      return res.status(404).json({ message: "Post not found" });
    }

    res.status(200).json(postData);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error fetching post" });
  }
});

// Update Post (admin only) - Connected
app.put(
  "/post/:id",
  authenticate,
  checkPermission("update"),
  async (req, res) => {
    try {
      const postId = req.params.id;
      if (!mongoose.Types.ObjectId.isValid(postId)) {
        return res.status(400).json({ message: "Invalid post ID" });
      }
      const categoryId = req.body.category;
      if (!mongoose.Types.ObjectId.isValid(categoryId)) {
        return res.status(400).json({ message: "Invalid category ID" });
      }

      const category = await Category.findById(categoryId);
      if (!category) {
        return res.status(400).json({ message: "Category not found" });
      }

      delete req.body.postedBy; // Delete postedBy field from request body
      const postData = await Post.findByIdAndUpdate(postId, req.body, {
        new: true,
      });
      if (!postData) {
        return res.status(404).json({ message: "Post not found" });
      }
      res.status(200).json({ message: "Post updated successfully", postData });
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: "Error updating post" });
    }
  }
);

// Delete Post (admin only) - Connected
app.delete(
  "/post/:id",
  authenticate,
  checkPermission("delete"),
  async (req, res) => {
    try {
      const postId = req.params.id;
      if (!mongoose.Types.ObjectId.isValid(postId)) {
        return res.status(400).json({ message: "Invalid post ID" });
      }

      const postDoc = await Post.findByIdAndDelete(postId);
      if (!postDoc) {
        return res.status(404).json({ message: "Post not found" });
      }

      res.status(200).json({ message: "Post deleted successfully" });
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: "Error deleting post" });
    }
  }
);

// SEARCH FUNCTIONALITY

// Search Posts (admin and user) - Connected
app.get("/search/posts", async (req, res) => {
    try {
      const query = req.query.q;
      const page = 1;
      const limit = 10;
      if (!query) {
        return res.status(400).json({ message: "Search query is required" });
      }

      const regex = new RegExp(query, "i");
      const posts = await Post.find({
        $or: [
          { title: regex },
          { description: regex },
          { content: regex },
          { tag: regex },
        ],
      })
        .populate("category")
        .skip((page - 1) * limit)
        .limit(limit);
      const totalPosts = await Post.countDocuments({
        $or: [
          { title: regex },
          { description: regex },
          { content: regex },
          { tag: regex },
        ],
      });
      const totalPages = Math.ceil(totalPosts / limit);
      res.status(200).json({
        posts,
        pagination: {
          currentPage: page,
          totalPages,
          totalPosts,
        },
      });
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: "Error searching posts" });
    }
  }
);

// Filter Posts by Category (admin and user) - Connected
app.get("/posts/filter", async (req, res) => {
    try {
      const categoryId = req.query.category;
      const page = 1;
      const limit = 10;
      if (!categoryId) {
        return res.status(400).json({ message: "Category ID is required" });
      }

      const posts = await Post.find({ category: categoryId })
        .populate("category")
        .populate("category")
        .skip((page - 1) * limit)
        .limit(limit);
      const totalPosts = await Post.countDocuments({ category: categoryId });
      const totalPages = Math.ceil(totalPosts / limit);
      res.status(200).json({
        posts,
        pagination: {
          currentPage: page,
          totalPages,
          totalPosts,
        },
      });
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: "Error filtering posts" });
    }
  }
);

// Paginate Posts (admin and user) - Connected
app.get("/posts", async (req, res) => {
  try {
    const page = req.query.page || 1;
    const limit = 5; // Should be 10

    const posts = await Post.find()
      .populate("category")
      .skip((page - 1) * limit)
      .limit(limit);

    const totalPosts = await Post.countDocuments();
    const totalPages = Math.ceil(totalPosts / limit);

    res.status(200).json({
      posts,
      pagination: {
        currentPage: page,
        totalPages,
        totalPosts,
      },
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error fetching posts" });
  }
});

// COMMENT AND REPLY FUNCTIONALITY

// Create Comment or Reply (only user) - Connected
app.post("/posts/:postId/comments", async (req, res) => {
  try {
    const postId = req.params.postId;
    const { username, email, comment, parentCommentId } = req.body;

    const newComment = new Comment({
      postId,
      username,
      email,
      comment,
      parentCommentId,
    });

    await newComment.save();

    if (parentCommentId) {
      // If it's a reply, add the comment ID to the parent comment's replies array
      await Comment.findByIdAndUpdate(parentCommentId, {
        $push: { replies: newComment._id },
      });
    }

    res.status(201).json(newComment);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error creating comment" });
  }
});

// Get Comment or Reply (only user) - Connected
app.get("/posts/:postId/comments", async (req, res) => {
  try {
    const postId = req.params.postId;

    const comments = await Comment.find({
      postId,
      parentCommentId: null,
    }).populate({
      path: "replies",
      populate: {
        path: "replies",
      },
    });

    res.status(200).json(comments);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error getting comments" });
  }
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
