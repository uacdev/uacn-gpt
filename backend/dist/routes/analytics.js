"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyticsRouter = void 0;
const express_1 = __importDefault(require("express"));
const User_1 = require("../models/User");
const AdminUser_1 = require("../models/AdminUser");
const Conversation_1 = require("../models/Conversation");
const Policy_1 = require("../models/Policy");
const BusinessUnit_1 = require("../models/BusinessUnit");
const BusinessUnitEmailMapping_1 = require("../models/BusinessUnitEmailMapping");
exports.analyticsRouter = express_1.default.Router();
// Verify admin token
const verifyAdminToken = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;
        if (!token) {
            return res.status(401).json({ error: "No token provided" });
        }
        const jwt = require("jsonwebtoken");
        const JWT_SECRET = process.env.UACN_GPT_JWT_SECRET || "your-secret-key-change-in-production";
        const decoded = jwt.verify(token, JWT_SECRET);
        if (!decoded.isAdmin) {
            return res.status(403).json({ error: "Admin access required" });
        }
        req.adminId = decoded.adminId;
        next();
    }
    catch (error) {
        return res.status(401).json({ error: "Invalid token" });
    }
};
// Get overall dashboard stats
exports.analyticsRouter.get("/dashboard", verifyAdminToken, async (req, res) => {
    try {
        const totalUsers = await User_1.User.countDocuments();
        const totalAdmins = await AdminUser_1.AdminUser.countDocuments();
        const totalConversations = await Conversation_1.Conversation.countDocuments();
        const totalPolicies = await Policy_1.Policy.countDocuments();
        res.json({
            totalUsers,
            totalAdmins,
            totalConversations,
            totalPolicies
        });
    }
    catch (error) {
        console.error("Dashboard stats error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
// Get stats by business unit
exports.analyticsRouter.get("/business-units", verifyAdminToken, async (req, res) => {
    try {
        const BUS = ["GCL", "LSF", "CAP", "UFL", "CHI", "UAC-Restaurants", "UPDC"];
        const stats = await Promise.all(BUS.map(async (bu) => {
            const userCount = await User_1.User.countDocuments({ businessUnit: bu });
            const adminCount = await AdminUser_1.AdminUser.countDocuments({ businessUnit: bu });
            const conversationCount = await Conversation_1.Conversation.countDocuments({ "userId": { $exists: true } });
            // Note: Conversations don't have businessUnit field directly, so this is approximate
            return {
                name: bu,
                users: userCount,
                admins: adminCount,
                conversations: conversationCount
            };
        }));
        res.json({ stats });
    }
    catch (error) {
        console.error("BU stats error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
// Get popular policies
exports.analyticsRouter.get("/popular-policies", verifyAdminToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        // Get policies sorted by relevance (for now, just by creation date, in real app you'd track views)
        const policies = await Policy_1.Policy.find({}, { title: 1, category: 1, businessUnit: 1, createdAt: 1 })
            .sort({ createdAt: -1 })
            .limit(limit)
            .lean();
        res.json({ policies });
    }
    catch (error) {
        console.error("Popular policies error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
// Get chat activity metrics
exports.analyticsRouter.get("/chat-activity", verifyAdminToken, async (req, res) => {
    try {
        // Get conversations created in last 7 days
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        const dailyActivity = await Conversation_1.Conversation.aggregate([
            {
                $match: {
                    createdAt: { $gte: sevenDaysAgo }
                }
            },
            {
                $group: {
                    _id: {
                        $dateToString: { format: "%Y-%m-%d", date: "$createdAt" }
                    },
                    count: { $sum: 1 }
                }
            },
            {
                $sort: { _id: 1 }
            }
        ]);
        res.json({ dailyActivity });
    }
    catch (error) {
        console.error("Chat activity error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
// Get usage by business unit
exports.analyticsRouter.get("/usage-by-bu", verifyAdminToken, async (req, res) => {
    try {
        const BUS = ["GCL", "LSF", "CAP", "UFL", "CHI", "UAC-Restaurants", "UPDC"];
        const usageData = await Promise.all(BUS.map(async (bu) => {
            const userCount = await User_1.User.countDocuments({ businessUnit: bu });
            return {
                bu,
                users: userCount
            };
        }));
        res.json({ usageData });
    }
    catch (error) {
        console.error("Usage by BU error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
// Reset user password
exports.analyticsRouter.post("/reset-password", verifyAdminToken, async (req, res) => {
    try {
        const { userId, newPassword } = req.body;
        if (!userId || !newPassword || newPassword.length < 6) {
            return res.status(400).json({ error: "userId and newPassword (min 6 chars) are required" });
        }
        const bcrypt = require("bcryptjs");
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const user = await User_1.User.findByIdAndUpdate(userId, { password: hashedPassword }, { new: true }).select("-password");
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        res.json({ message: "Password reset successfully", user });
    }
    catch (error) {
        console.error("Reset password error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
// Get all business units
exports.analyticsRouter.get("/business-units-list", verifyAdminToken, async (req, res) => {
    try {
        const buses = await BusinessUnit_1.BusinessUnit.find().select("name label").sort("name");
        const businessUnits = buses.map((bu) => ({
            name: bu.name,
            label: bu.label,
            _id: bu._id
        }));
        res.json({ businessUnits });
    }
    catch (error) {
        console.error("Get BU list error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
// Add new business unit (superadmin only)
exports.analyticsRouter.post("/business-units", verifyAdminToken, async (req, res) => {
    try {
        const { name, label } = req.body;
        if (!name || !label) {
            return res.status(400).json({ error: "Name and label are required" });
        }
        // Check if BU already exists
        const existingBU = await BusinessUnit_1.BusinessUnit.findOne({ name });
        if (existingBU) {
            return res.status(409).json({ error: "Business unit already exists" });
        }
        const newBU = new BusinessUnit_1.BusinessUnit({ name, label });
        await newBU.save();
        res.status(201).json({ message: "Business unit created", businessUnit: newBU });
    }
    catch (error) {
        console.error("Add BU error:", error);
        if (error.code === 11000) {
            return res.status(409).json({ error: "Business unit name already exists" });
        }
        res.status(500).json({ error: "Internal server error" });
    }
});
// Update business unit (superadmin only)
exports.analyticsRouter.put("/business-units/:id", verifyAdminToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, label } = req.body;
        if (!name || !label) {
            return res.status(400).json({ error: "Name and label are required" });
        }
        // Check if another BU has this name
        const existingBU = await BusinessUnit_1.BusinessUnit.findOne({ name, _id: { $ne: id } });
        if (existingBU) {
            return res.status(409).json({ error: "Business unit name already exists" });
        }
        const updated = await BusinessUnit_1.BusinessUnit.findByIdAndUpdate(id, { name, label }, { new: true });
        if (!updated) {
            return res.status(404).json({ error: "Business unit not found" });
        }
        res.json({ message: "Business unit updated", businessUnit: updated });
    }
    catch (error) {
        console.error("Update BU error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
// Delete business unit (superadmin only)
exports.analyticsRouter.delete("/business-units/:id", verifyAdminToken, async (req, res) => {
    try {
        const { id } = req.params;
        // Check if any admins or users are assigned to this BU
        const adminCount = await AdminUser_1.AdminUser.countDocuments({ businessUnit: id });
        const userCount = await User_1.User.countDocuments({ businessUnit: id });
        if (adminCount > 0 || userCount > 0) {
            return res.status(400).json({
                error: "Cannot delete business unit with assigned users or admins",
                details: { admins: adminCount, users: userCount }
            });
        }
        const deleted = await BusinessUnit_1.BusinessUnit.findByIdAndDelete(id);
        if (!deleted) {
            return res.status(404).json({ error: "Business unit not found" });
        }
        res.json({ message: "Business unit deleted", businessUnit: deleted });
    }
    catch (error) {
        console.error("Delete BU error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
// Get all email domain mappings
exports.analyticsRouter.get("/email-domains", verifyAdminToken, async (req, res) => {
    try {
        const domains = await BusinessUnitEmailMapping_1.BusinessUnitEmailMapping.find().sort({ businessUnit: 1 });
        res.json({ domains });
    }
    catch (error) {
        console.error("Error fetching email domains:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
// Create or update email domain mapping
exports.analyticsRouter.post("/email-domain", verifyAdminToken, async (req, res) => {
    try {
        const { businessUnit, emailDomain } = req.body;
        if (!businessUnit || !emailDomain) {
            return res.status(400).json({ error: "Business unit and email domain are required" });
        }
        // Validate that the business unit exists
        const buExists = await BusinessUnit_1.BusinessUnit.findOne({ name: businessUnit });
        if (!buExists) {
            return res.status(400).json({ error: "Business unit does not exist" });
        }
        // Upsert the email domain mapping
        const mapping = await BusinessUnitEmailMapping_1.BusinessUnitEmailMapping.findOneAndUpdate({ businessUnit }, { businessUnit, emailDomain: emailDomain.toLowerCase() }, { upsert: true, new: true });
        res.json({
            message: "Email domain mapping saved successfully",
            domain: mapping
        });
    }
    catch (error) {
        console.error("Error saving email domain:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
// Delete email domain mapping
exports.analyticsRouter.delete("/email-domain/:id", verifyAdminToken, async (req, res) => {
    try {
        const { id } = req.params;
        const deleted = await BusinessUnitEmailMapping_1.BusinessUnitEmailMapping.findByIdAndDelete(id);
        if (!deleted) {
            return res.status(404).json({ error: "Email domain mapping not found" });
        }
        res.json({ message: "Email domain mapping deleted successfully" });
    }
    catch (error) {
        console.error("Error deleting email domain:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
