import User from "../models/user.model.js";
import jwt from "jsonwebtoken";

export const protectRoute = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    if (!token) {
      return res.status(401).json({ error: "Not authorized, no token" });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded) {
      return res.status(401).json({ error: "Not authorized, token failed" });
    }
    const user = await User.findById(decoded.userId).select("-password"); // Exclude password
    if (!user) {
      return res.status(401).json({ error: "Not authorized, user not found" });
    }
    req.user = user;
    next();
  } catch (error) {
    console.log("Protect route error:", error);
    return res.status(500).json({ error: "internal server error" });
  }
};
