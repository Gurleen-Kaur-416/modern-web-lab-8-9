import { userAdminService } from "../services/userAdminService.js";
import { successResponse } from "../utils/apiResponse.js";

export const userAdminController = {
  async listUsers(req, res, next) {
    try {
      const data = await userAdminService.listUsers();
      return successResponse(res, data, "Users loaded");
    } catch (error) {
      next(error);
    }
  },

  async listCustomers(req, res, next) {
    try {
      const data = await userAdminService.listCustomers();
      return successResponse(res, data, "Customers loaded");
    } catch (error) {
      next(error);
    }
 },

  async updateUserStatus(req, res, next) {
    try {
      const data = await userAdminService.updateUserStatus(
        req.params.userId,
        req.body.accountStatus
      );
      return successResponse(res, data, "User status updated");
    } catch (error) {
      next(error);
    }
  }
  
};