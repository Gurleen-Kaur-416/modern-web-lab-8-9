import { dashboardService } from "../services/dashboardService.js";
import { successResponse } from "../utils/apiResponse.js";

export const dashboardController = {
  async getSummary(req, res, next) {
    try {
      const data = await dashboardService.getSummary();
      return successResponse(res, data, "Dashboard summary loaded");
    } catch (error) {
      next(error);
    }
  }
};