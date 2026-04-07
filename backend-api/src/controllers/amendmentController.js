import { amendmentService } from "../services/amendmentService.js";
import { successResponse } from "../utils/apiResponse.js";

export const amendmentController = {
  async listAmendments(req, res, next) {
    try {
      const data = await amendmentService.listAll();
      return successResponse(res, data, "Amendments loaded");
    } catch (error) {
      next(error);
    }
  },

  async getAmendmentById(req, res, next) {
    try {
      const data = await amendmentService.getById(req.params.amendmentId);
      return successResponse(res, data, "Amendment loaded");
    } catch (error) {
      next(error);
    }
  },

  async createAmendment(req, res, next) {
    try {
      const data = await amendmentService.create(req.body, req.user);
      return successResponse(res, data, "Amendment request created", 201);
    } catch (error) {
      next(error);
    }
  },

  async reviewAmendment(req, res, next) {
    try {
      const data = await amendmentService.review(
        req.params.amendmentId,
        req.body,
        req.user
      );

      return successResponse(res, data, "Amendment reviewed");
    } catch (error) {
      next(error);
    }
  },

  async deleteAmendment(req, res, next) {
    try {
      await amendmentService.delete(req.params.amendmentId, req.user);
      return successResponse(res, null, "Amendment deleted");
    } catch (error) {
      next(error);
    }
  }
};