import { reductionService } from "../services/reductionService.js";
import { successResponse } from "../utils/apiResponse.js";

function getRoleNames(user) {
  return (user?.roles || []).map((role) => {
    if (typeof role === "string") {
      return role;
    }

    if (role && typeof role === "object" && role.name) {
      return role.name;
    }

    return String(role);
  });
}

export const reductionController = {
  async listReductions(req, res, next) {
    try {
      const roleNames = getRoleNames(req.user);
      const isCustomer = roleNames.includes("CUSTOMER");

      const data = isCustomer
        ? await reductionService.listForCustomer(req.user._id)
        : await reductionService.listAll();

      return successResponse(res, data, "Reduction requests loaded");
    } catch (error) {
      next(error);
    }
  },

  async getReductionById(req, res, next) {
    try {
      const data = await reductionService.getById(req.params.reductionId);
      return successResponse(res, data, "Reduction request loaded");
    } catch (error) {
      next(error);
    }
  },

  async createReduction(req, res, next) {
    try {
      const data = await reductionService.create(req.body, req.user);
      return successResponse(res, data, "Reduction request created", 201);
    } catch (error) {
      next(error);
    }
  },

  async reviewReduction(req, res, next) {
    try {
      const data = await reductionService.review(
        req.params.reductionId,
        req.body,
        req.user
      );

      return successResponse(res, data, "Reduction request reviewed");
    } catch (error) {
      next(error);
    }
  },

  async deleteReduction(req, res, next) {
    try {
      await reductionService.delete(req.params.reductionId, req.user);
      return successResponse(res, null, "Reduction deleted");
    } catch (error) {
      next(error);
    }
  }
};