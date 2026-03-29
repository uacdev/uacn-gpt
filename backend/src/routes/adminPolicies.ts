import express from "express";
import multer from "multer";
import { Policy } from "../models/Policy";
import { adminAuthMiddleware, AuthenticatedRequest } from "../middleware/auth";
import { extractTextFromDocx } from "../utils/docxParser";
import { extractTextFromPdf } from "../utils/pdfParser";

export const adminPoliciesRouter = express.Router();

// Configure multer for file uploads (in-memory storage)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    // Accept .docx, .pdf, and text files
    if (
      file.mimetype === "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
      file.mimetype === "application/pdf" ||
      file.mimetype === "text/plain"
    ) {
      cb(null, true);
    } else {
      cb(new Error("Only .docx, .pdf, and .txt files are allowed"));
    }
  }
});

// Protect all admin policy routes: require authenticated admin
adminPoliciesRouter.use(adminAuthMiddleware);

// List all policies for the admin's business unit
adminPoliciesRouter.get("/", async (req: AuthenticatedRequest, res) => {
  try {
    const businessUnit = req.businessUnit;
    
    if (!businessUnit) {
      return res.status(400).json({ error: "Business unit not found in token" });
    }

    const policies = await Policy.find({ businessUnit }).sort({ createdAt: -1 }).lean();
    res.json(policies);
  } catch (err) {
    console.error("Error listing policies", err);
    res.status(500).json({ error: "Failed to list policies" });
  }
});

// Create a new policy for the admin's business unit (text or from file)
adminPoliciesRouter.post("/", upload.single("file"), async (req: AuthenticatedRequest, res) => {
  try {
    const { title, category, content, tags } = req.body;
    const businessUnit = req.businessUnit;
    const file = req.file;
    const adminId = req.adminId;
    const adminEmail = req.email;
    const adminName = req.fullName;

    if (!businessUnit) {
      return res.status(400).json({ error: "Business unit not found in token" });
    }

    let policyContent = content;
    let sourceFile;

    // If a file was uploaded, extract content from it
    if (file) {
      if (file.mimetype === "application/vnd.openxmlformats-officedocument.wordprocessingml.document") {
        // Extract text from .docx file
        try {
          policyContent = await extractTextFromDocx(file.buffer);
        } catch (err) {
          console.error("Error extracting text from DOCX:", err);
          return res.status(400).json({ error: "Failed to parse Word document. Make sure it's a valid .docx file." });
        }
        sourceFile = {
          filename: file.originalname,
          fileType: "docx",
          uploadedAt: new Date()
        };
      } else if (file.mimetype === "text/plain") {
        // Extract text from .txt file
        policyContent = file.buffer.toString("utf-8");
        sourceFile = {
          filename: file.originalname,
          fileType: "text",
          uploadedAt: new Date()
        };
      } else if (file.mimetype === "application/pdf") {
        // Extract text from PDF file
        try {
          policyContent = await extractTextFromPdf(file.buffer);
        } catch (err) {
          console.error("Error extracting text from PDF:", err);
          return res.status(400).json({ error: "Failed to parse PDF document. Make sure it's a valid PDF file." });
        }
        sourceFile = {
          filename: file.originalname,
          fileType: "pdf",
          uploadedAt: new Date()
        };
      }
    }

    // Validate that we have content from either text input or file
    if (!title || !category || !policyContent) {
      return res
        .status(400)
        .json({ error: "title, category and content (or file) are required" });
    }

    const policy = await Policy.create({
      title,
      category,
      content: policyContent,
      businessUnit,
      uploadedBy: {
        adminId: adminId || "unknown",
        adminEmail: adminEmail || "unknown",
        adminName: adminName || "Unknown User"
      },
      sourceFile: sourceFile,
      tags: Array.isArray(tags)
        ? tags
        : typeof tags === "string"
        ? tags
            .split(",")
            .map((t: string) => t.trim())
            .filter(Boolean)
        : []
    });

    res.status(201).json(policy);
  } catch (err) {
    console.error("Error creating policy", err);
    res.status(500).json({ error: "Failed to create policy" });
  }
});

// Update an existing policy (only if it belongs to the admin's business unit)
adminPoliciesRouter.put("/:id", async (req: AuthenticatedRequest, res) => {
  try {
    const { id } = req.params;
    const { title, category, content, tags } = req.body;
    const businessUnit = req.businessUnit;

    if (!businessUnit) {
      return res.status(400).json({ error: "Business unit not found in token" });
    }

    // First check if the policy belongs to this admin's business unit
    const existingPolicy = await Policy.findById(id);
    if (!existingPolicy) {
      return res.status(404).json({ error: "Policy not found" });
    }

    if (existingPolicy.businessUnit !== businessUnit) {
      return res.status(403).json({ error: "Unauthorized: Cannot modify policy from another business unit" });
    }

    const updated = await Policy.findByIdAndUpdate(
      id,
      {
        title,
        category,
        content,
        tags: Array.isArray(tags)
          ? tags
          : typeof tags === "string"
          ? tags
              .split(",")
              .map((t: string) => t.trim())
              .filter(Boolean)
          : []
      },
      { new: true }
    );

    res.json(updated);
  } catch (err) {
    console.error("Error updating policy", err);
    res.status(500).json({ error: "Failed to update policy" });
  }
});

// Delete a policy (only if it belongs to the admin's business unit)
adminPoliciesRouter.delete("/:id", async (req: AuthenticatedRequest, res) => {
  try {
    const { id } = req.params;
    const businessUnit = req.businessUnit;

    if (!businessUnit) {
      return res.status(400).json({ error: "Business unit not found in token" });
    }

    // First check if the policy belongs to this admin's business unit
    const existingPolicy = await Policy.findById(id);
    if (!existingPolicy) {
      return res.status(404).json({ error: "Policy not found" });
    }

    if (existingPolicy.businessUnit !== businessUnit) {
      return res.status(403).json({ error: "Unauthorized: Cannot delete policy from another business unit" });
    }

    const deleted = await Policy.findByIdAndDelete(id);
    if (!deleted) {
      return res.status(404).json({ error: "Policy not found" });
    }
    res.json({ success: true });
  } catch (err) {
    console.error("Error deleting policy", err);
    res.status(500).json({ error: "Failed to delete policy" });
  }
});
