import { profileService } from "../services/profileService.js";
import { successResponse } from "../utils/apiResponse.js";

export const profileController = {
  async getOwnProfile(req, res, next) {
    try {
      const data = await profileService.getOwnProfile(req.user._id);
      return successResponse(res, data, "Profile loaded");
    } catch (error) {
      next(error);
    }
  },

  async updateOwnProfile(req, res, next) {
    try {
      const data = await profileService.updateOwnProfile(req.user._id, req.body);
      return successResponse(res, data, "Profile updated");
    } catch (error) {
      next(error);
    }
  }
};