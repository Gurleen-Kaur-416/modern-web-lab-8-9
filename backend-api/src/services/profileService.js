import { User } from "../models/User.js";
import { AppError } from "../utils/appError.js";
import { stripSensitiveUserFields } from "../utils/safeObject.js";

export const profileService = {
  async getOwnProfile(userId) {
    const user = await User.findById(userId).populate("roles");
    if (!user) {
      throw new AppError("User not found", 404);
    }
    return stripSensitiveUserFields(user);
  },

  async updateOwnProfile(userId, updates) {
    const user = await User.findById(userId).populate("roles");
    if (!user) {
      throw new AppError("User not found", 404);
    }

    Object.assign(user.profile, updates);
    await user.save();

    const refreshedUser = await User.findById(userId).populate("roles");
    return stripSensitiveUserFields(refreshedUser);
  }
};