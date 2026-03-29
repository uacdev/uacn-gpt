import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export interface AuthenticatedRequest extends Request {
  userId?: string;
  email?: string;
  businessUnit?: string;
  adminId?: string;
  fullName?: string;
  isAdmin?: boolean;
}

const JWT_SECRET = process.env.UACN_GPT_JWT_SECRET || "your-secret-key-change-in-production";
const ADMIN_JWT_SECRET = process.env.UACN_GPT_JWT_SECRET || "your-secret-key-change-in-production";

export const authMiddleware = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Authorization token required" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    req.userId = decoded.userId;
    req.email = decoded.email;
    req.businessUnit = decoded.businessUnit;
    next();
  } catch (error) {
    res.status(401).json({ error: "Invalid or expired token" });
  }
};

export const adminAuthMiddleware = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Admin authorization token required" });
  }

  try {
    const decoded = jwt.verify(token, ADMIN_JWT_SECRET) as any;
    
    if (!decoded.isAdmin) {
      return res.status(403).json({ error: "Admin access required" });
    }
    req.adminId = decoded.adminId;
    req.email = decoded.email;
    req.fullName = decoded.fullName;
    req.businessUnit = decoded.businessUnit;
    req.isAdmin = decoded.isAdmin;
    next();
  } catch (error: any) {
    res.status(401).json({ error: "Invalid or expired admin token" });
  }
};
