import { Resend } from "resend";
import dotenv from "dotenv";

dotenv.config();

const resend = new Resend(process.env.RESEND_API_KEY);
const FRONTEND_URL = process.env.FRONTEND_URL || "http://0.0.0.0:3000";
const FROM_EMAIL = process.env.FROM_EMAIL || "noreply@uacngpt.com";

interface EmailOptions {
  to: string;
  subject: string;
  html: string;
}

/**
 * Send email verification OTP
 */
export async function sendVerificationEmail(
  email: string,
  otp: string,
  fullName: string,
  businessUnit: string
): Promise<void> {
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 20px; text-align: center; border-radius: 8px 8px 0 0;">
        <h1 style="color: white; margin: 0;">Welcome to UACN GPT</h1>
      </div>
      <div style="padding: 40px 20px; background: #f9f9f9;">
        <p style="color: #333; font-size: 16px;">Hi ${fullName},</p>
        <p style="color: #555; line-height: 1.6;">Thank you for signing up! To complete your registration, please enter the OTP code below:</p>
        
        <div style="margin: 30px 0; text-align: center; background: white; padding: 20px; border-radius: 8px; border: 2px solid #667eea;">
          <p style="color: #999; font-size: 12px; margin: 0 0 10px 0;">Your Verification Code</p>
          <p style="font-size: 32px; font-weight: bold; color: #667eea; margin: 0; letter-spacing: 4px;">${otp}</p>
        </div>
        
        <p style="color: #666; font-size: 14px; text-align: center;">This code will expire in 10 minutes.</p>
        <p style="color: #999; font-size: 12px; margin-top: 20px;">If you didn't sign up for this account, please ignore this email.</p>
      </div>
      <div style="padding: 20px; background: #f0f0f0; text-align: center; border-radius: 0 0 8px 8px;">
        <p style="color: #999; font-size: 12px; margin: 0;">© 2024 UACN GPT. All rights reserved.</p>
      </div>
    </div>
  `;

  const emailOptions: EmailOptions = {
    to: email,
    subject: `Your [${businessUnit}] GPT Email Verification Code`,
    html,
  };

  try {
    const response = await resend.emails.send({
      from: FROM_EMAIL,
      ...emailOptions,
    });

    if (response.error) {
      throw new Error(`Failed to send verification email: ${response.error.message}`);
    }

    console.log(`Verification OTP sent to ${email}`);
  } catch (error) {
    console.error("Error sending verification email:", error);
    throw error;
  }
}

/**
 * Send password reset link
 */
export async function sendPasswordResetEmail(
  email: string,
  resetToken: string,
  fullName: string
): Promise<void> {
  const resetLink = `${FRONTEND_URL}/reset-password?token=${resetToken}`;

  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 20px; text-align: center; border-radius: 8px 8px 0 0;">
        <h1 style="color: white; margin: 0;">Password Reset Request</h1>
      </div>
      <div style="padding: 40px 20px; background: #f9f9f9;">
        <p style="color: #333; font-size: 16px;">Hi ${fullName},</p>
        <p style="color: #555; line-height: 1.6;">We received a request to reset your password. If you didn't make this request, you can ignore this email. Otherwise, click the button below to reset your password:</p>
        
        <div style="margin: 30px 0; text-align: center;">
          <a href="${resetLink}" style="display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-size: 16px; font-weight: bold;">Reset Password</a>
        </div>
        
        <p style="color: #666; font-size: 14px;">Or copy and paste this link in your browser:</p>
        <p style="color: #667eea; font-size: 12px; word-break: break-all;">${resetLink}</p>
        
        <p style="color: #999; font-size: 12px; margin-top: 30px;">This link will expire in 1 hour.</p>
        <p style="color: #999; font-size: 12px;">If you need help, please contact our support team.</p>
      </div>
      <div style="padding: 20px; background: #f0f0f0; text-align: center; border-radius: 0 0 8px 8px;">
        <p style="color: #999; font-size: 12px; margin: 0;">© 2024 UACN GPT. All rights reserved.</p>
      </div>
    </div>
  `;

  const emailOptions: EmailOptions = {
    to: email,
    subject: "Reset Your UACN GPT Password",
    html,
  };

  try {
    const response = await resend.emails.send({
      from: FROM_EMAIL,
      ...emailOptions,
    });

    if (response.error) {
      throw new Error(`Failed to send reset email: ${response.error.message}`);
    }

    console.log(`Password reset email sent to ${email}`);
  } catch (error) {
    console.error("Error sending password reset email:", error);
    throw error;
  }
}

/**
 * Send welcome email after successful email verification
 */
export async function sendWelcomeEmail(email: string, fullName: string): Promise<void> {
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 20px; text-align: center; border-radius: 8px 8px 0 0;">
        <h1 style="color: white; margin: 0;">Welcome to UACN GPT!</h1>
      </div>
      <div style="padding: 40px 20px; background: #f9f9f9;">
        <p style="color: #333; font-size: 16px;">Hi ${fullName},</p>
        <p style="color: #555; line-height: 1.6;">Your email has been verified successfully! Your account is now active and ready to use.</p>
        
        <p style="color: #555; line-height: 1.6;">You can now:</p>
        <ul style="color: #555; line-height: 1.8;">
          <li>Chat with our AI assistant</li>
          <li>Access company policies and information</li>
          <li>Get instant answers to your questions</li>
        </ul>
        
        <div style="margin: 30px 0; text-align: center;">
          <a href="${FRONTEND_URL}/dashboard" style="display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-size: 16px; font-weight: bold;">Go to Dashboard</a>
        </div>
        
        <p style="color: #999; font-size: 12px; margin-top: 30px;">If you have any questions, feel free to reach out to our support team.</p>
      </div>
      <div style="padding: 20px; background: #f0f0f0; text-align: center; border-radius: 0 0 8px 8px;">
        <p style="color: #999; font-size: 12px; margin: 0;">© 2024 UACN GPT. All rights reserved.</p>
      </div>
    </div>
  `;

  const emailOptions: EmailOptions = {
    to: email,
    subject: "Welcome to UACN GPT - Your Account is Active!",
    html,
  };

  try {
    const response = await resend.emails.send({
      from: FROM_EMAIL,
      ...emailOptions,
    });

    if (response.error) {
      throw new Error(`Failed to send welcome email: ${response.error.message}`);
    }

    console.log(`Welcome email sent to ${email}`);
  } catch (error) {
    console.error("Error sending welcome email:", error);
    throw error;
  }
}
