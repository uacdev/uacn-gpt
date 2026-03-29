import express, { Request, Response } from "express";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { AdminUser, type BusinessUnit } from "../models/AdminUser";
import { User } from "../models/User";
import { BusinessUnit as BusinessUnitModel } from "../models/BusinessUnit";
import { BusinessUnitEmailMapping } from "../models/BusinessUnitEmailMapping";
import { sendVerificationEmail, sendPasswordResetEmail, sendWelcomeEmail } from "../services/emailService";

export const adminAuthRouter = express.Router();

interface AdminAuthRequest {
  email: string;
  password: string;
  fullName?: string;
  businessUnit?: BusinessUnit;
}

const JWT_SECRET = process.env.UACN_GPT_JWT_SECRET || "your-secret-key-change-in-production";

// Helper function to generate 6-digit OTP
function generateOTP(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper function to generate token hash for password reset
function generateToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// Admin Register endpoint (with email verification OTP)
adminAuthRouter.post("/register", async (req: Request<{}, {}, AdminAuthRequest>, res: Response) => {
  try {
    const { email, password, fullName, businessUnit } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // Validate password strength
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters long" });
    }

    // Check if admin exists
    const existingAdmin = await AdminUser.findOne({ email: email.toLowerCase() });
    if (existingAdmin) {
      return res.status(409).json({ error: "Admin already exists" });
    }

    // Hash password
    const hashedPassword = await bcryptjs.hash(password, 10);

    // For C-Panel superadmin registration (no BU specified), use defaults
    const adminFullName = fullName || "Superadmin";
    const adminBU = businessUnit || ("SUPERADMIN" as BusinessUnit);

    // Validate business unit exists if specified (and not SUPERADMIN)
    if (businessUnit && businessUnit !== "SUPERADMIN") {
      const validBU = await BusinessUnitModel.findOne({ name: businessUnit });
      if (!validBU) {
        return res.status(400).json({ error: "Invalid business unit" });
      }
    }

    // Validate email domain matches business unit (only if BU is specified, not for superadmin)
    if (businessUnit && businessUnit !== "SUPERADMIN") {
      const emailDomainMapping = await BusinessUnitEmailMapping.findOne({ businessUnit });
      if (emailDomainMapping) {
        const emailDomain = email.toLowerCase().split('@')[1];
        const expectedDomain = emailDomainMapping.emailDomain.toLowerCase();
        
        if (!emailDomain || emailDomain !== expectedDomain) {
          return res.status(400).json({ 
            error: `Invalid email domain for ${businessUnit}. Your email must end with @${expectedDomain}` 
          });
        }
      } else {
        // If a mapping exists for any business unit, all non-superadmin registrations must validate
        const anyMappingExists = await BusinessUnitEmailMapping.countDocuments();
        if (anyMappingExists > 0) {
          return res.status(400).json({
            error: `Email domain mapping not configured for ${businessUnit}. Please contact your administrator to set up the email domain for this business unit.`
          });
        }
      }
    }

    // Generate 6-digit OTP
    const otp = generateOTP();

    // Create admin user (not verified yet)
    const admin = new AdminUser({
      email: email.toLowerCase(),
      password: hashedPassword,
      fullName: adminFullName,
      businessUnit: adminBU,
      emailVerified: false,
      emailVerificationOTP: otp,
      emailVerificationOTPExpiry: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    });

    await admin.save();

    // Send verification email with OTP
    try {
      await sendVerificationEmail(email.toLowerCase(), otp, adminFullName, adminBU);
    } catch (emailError) {
      console.error("Failed to send verification email:", emailError);
      return res.status(201).json({
        message: "Admin account created, but verification email could not be sent. Please try again or contact support.",
        user: {
          id: admin._id,
          email: admin.email,
          fullName: admin.fullName,
          businessUnit: admin.businessUnit,
          emailVerified: admin.emailVerified
        }
      });
    }

    res.status(201).json({
      message: "Admin account created successfully. Please check your email for the verification code.",
      user: {
        id: admin._id,
        email: admin.email,
        fullName: admin.fullName,
        businessUnit: admin.businessUnit,
        emailVerified: admin.emailVerified
      }
    });
  } catch (error) {
    console.error("Admin register error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin Login endpoint
adminAuthRouter.post("/login", async (req: Request<{}, {}, AdminAuthRequest>, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // Find admin
    const admin = await AdminUser.findOne({ email: email.toLowerCase() });
    if (!admin) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Check if email is verified (skip for SUPERADMIN)
    if (!admin.emailVerified && admin.businessUnit !== "SUPERADMIN") {
      return res.status(403).json({
        error: "Please verify your email before logging in",
        requiresVerification: true,
        email: admin.email
      });
    }

    // Compare password
    const passwordMatch = await bcryptjs.compare(password, admin.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Generate token
    const token = jwt.sign(
      { adminId: admin._id, email: admin.email, fullName: admin.fullName, businessUnit: admin.businessUnit, isAdmin: true },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      admin: {
        id: admin._id,
        email: admin.email,
        fullName: admin.fullName,
        businessUnit: admin.businessUnit,
        emailVerified: admin.emailVerified
      }
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Verify Email endpoint
adminAuthRouter.post("/verify-email", async (req: Request<{}, {}, { email: string; otp: string }>, res: Response) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ error: "Email and OTP are required" });
    }

    // Find admin with valid OTP
    const admin = await AdminUser.findOne({
      email: email.toLowerCase(),
      emailVerificationOTP: otp,
      emailVerificationOTPExpiry: { $gt: new Date() }
    });

    if (!admin) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    // Mark email as verified and clear OTP
    admin.emailVerified = true;
    admin.emailVerificationOTP = undefined;
    admin.emailVerificationOTPExpiry = undefined;
    await admin.save();

    // Send welcome email
    try {
      await sendWelcomeEmail(admin.email, admin.fullName);
    } catch (emailError) {
      console.error("Failed to send welcome email:", emailError);
    }

    res.json({
      message: "Email verified successfully! You can now login."
    });
  } catch (error) {
    console.error("Verify email error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Resend Verification Email endpoint
adminAuthRouter.post("/resend-verification", async (req: Request<{}, {}, { email: string }>, res: Response) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    // Find admin
    const admin = await AdminUser.findOne({ email: email.toLowerCase() });
    if (!admin) {
      return res.status(200).json({
        message: "If an account exists with this email, a verification code will be sent shortly"
      });
    }

    // If already verified
    if (admin.emailVerified) {
      return res.status(200).json({
        message: "This email is already verified. You can login now."
      });
    }

    // Generate new OTP
    const otp = generateOTP();

    admin.emailVerificationOTP = otp;
    admin.emailVerificationOTPExpiry = new Date(Date.now() + 10 * 60 * 1000);
    await admin.save();

    // Send verification email with new OTP
    try {
      await sendVerificationEmail(admin.email, otp, admin.fullName, admin.businessUnit);
    } catch (emailError) {
      console.error("Failed to send verification email:", emailError);
      return res.status(500).json({ error: "Failed to send verification code. Please try again." });
    }

    res.json({
      message: "Verification code sent. Please check your inbox."
    });
  } catch (error) {
    console.error("Resend verification error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Forgot Password endpoint
adminAuthRouter.post("/forgot-password", async (req: Request<{}, {}, { email: string }>, res: Response) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    // Find admin
    const admin = await AdminUser.findOne({ email: email.toLowerCase() });
    if (!admin) {
      return res.status(200).json({
        message: "If an account exists with this email, a reset link will be sent shortly"
      });
    }

    // Generate reset token
    const resetTokenRaw = crypto.randomBytes(32).toString("hex");
    const resetToken = generateToken(resetTokenRaw);

    // Set token expiry to 1 hour from now
    admin.resetToken = resetToken;
    admin.resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000);
    await admin.save();

    // Send password reset email
    try {
      await sendPasswordResetEmail(admin.email, resetTokenRaw, admin.fullName);
    } catch (emailError) {
      console.error("Failed to send reset email:", emailError);
      return res.status(500).json({ error: "Failed to send password reset email. Please try again." });
    }

    res.json({
      message: "If an account exists with this email, a reset link will be sent shortly"
    });
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Reset Password endpoint
adminAuthRouter.post("/reset-password", async (req: Request<{}, {}, { token: string; newPassword: string; email: string }>, res: Response) => {
  try {
    const { token, newPassword, email } = req.body;

    if (!token || !newPassword || !email) {
      return res.status(400).json({ error: "Token, email, and new password are required" });
    }

    // Validate password strength
    if (newPassword.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters long" });
    }

    // Hash the token to compare with stored hash
    const resetTokenHash = generateToken(token);

    // Find admin with valid reset token
    const admin = await AdminUser.findOne({
      email: email.toLowerCase(),
      resetToken: resetTokenHash,
      resetTokenExpiry: { $gt: new Date() }
    });

    if (!admin) {
      return res.status(400).json({ error: "Reset token is invalid or has expired" });
    }

    // Hash new password
    const hashedPassword = await bcryptjs.hash(newPassword, 10);

    // Update password and clear reset token
    admin.password = hashedPassword;
    admin.resetToken = undefined;
    admin.resetTokenExpiry = undefined;
    await admin.save();

    res.json({
      message: "Password reset successfully. You can now login with your new password."
    });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Middleware to verify admin token

const verifyAdminToken = (req: Request, res: Response, next: Function) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;

    if (!token) {
      return res.status(401).json({ error: "No token provided" });
    }

    const decoded = jwt.verify(token, JWT_SECRET) as any;
    (req as any).admin = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

// Get all BU admins (C-Panel endpoint)
adminAuthRouter.get("/admins", verifyAdminToken, async (req: Request, res: Response) => {
  try {
    const admins = await AdminUser.find({}, { password: 0 }).sort({ createdAt: -1 });
    res.json({ admins });
  } catch (error) {
    console.error("Get admins error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get users by business unit (C-Panel endpoint)
adminAuthRouter.get("/users", verifyAdminToken, async (req: Request, res: Response) => {
  try {
    const { businessUnit } = req.query;

    if (!businessUnit) {
      return res.status(400).json({ error: "businessUnit query parameter is required" });
    }

    // Fetch valid business units from database
    const validBUs = await BusinessUnitModel.find().select("name");
    const validBUNames = validBUs.map((bu: any) => bu.name);

    if (!validBUNames.includes(businessUnit as string)) {
      return res.status(400).json({ error: "Invalid business unit" });
    }

    const users = await User.find(
      { businessUnit },
      { password: 0, resetToken: 0, resetTokenExpiry: 0 }
    ).sort({ createdAt: -1 });

    res.json({ users });
  } catch (error) {
    console.error("Get users error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
