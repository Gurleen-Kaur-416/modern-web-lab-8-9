import { policyService } from "../services/policyService.js";
import { successResponse } from "../utils/apiResponse.js";
import { AppError } from "../utils/appError.js";

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

function resolveCurrentUserId(user) {
  return String(user?._id || user?.id || "");
}

function resolvePolicyCustomerId(policy) {
  if (!policy) {
    return "";
  }

  if (policy.customer?._id) {
    return String(policy.customer._id);
  }

  if (policy.customer) {
    return String(policy.customer);
  }

  if (policy.customerId) {
    return String(policy.customerId);
  }

  return "";
}

export const policyController = {
  async listPolicies(req, res, next) {
    try {
      const roleNames = getRoleNames(req.user);
      const isCustomer = roleNames.includes("CUSTOMER");
      const currentUserId = resolveCurrentUserId(req.user);

      if (isCustomer && !currentUserId) {
        throw new AppError("Authenticated customer id is missing", 401);
      }

      const data = isCustomer
        ? await policyService.listForCustomer(currentUserId)
        : await policyService.listAll();

      return successResponse(res, data, "Policies loaded");
    } catch (error) {
      next(error);
    }
  },

  async getPolicyById(req, res, next) {
    try {
      const policy = await policyService.getById(req.params.policyId);
      const roleNames = getRoleNames(req.user);
      const isCustomer = roleNames.includes("CUSTOMER");
      const currentUserId = resolveCurrentUserId(req.user);

      if (isCustomer && !currentUserId) {
        throw new AppError("Authenticated customer id is missing", 401);
      }

      if (isCustomer && resolvePolicyCustomerId(policy) !== currentUserId) {
        throw new AppError("Policy not found", 404);
      }

      return successResponse(res, policy, "Policy loaded");
    } catch (error) {
      next(error);
    }
  },

  async createPolicy(req, res, next) {
    try {
      const createdBy = resolveCurrentUserId(req.user);

      if (!createdBy) {
        throw new AppError("Authenticated user id is missing", 401);
      }

      const data = await policyService.create({
        ...req.body,
        createdBy
      });

      return successResponse(res, data, "Policy created", 201);
    } catch (error) {
      next(error);
    }
  },

  async updatePolicy(req, res, next) {
    try {
      const data = await policyService.update(req.params.policyId, req.body);
      return successResponse(res, data, "Policy updated");
    } catch (error) {
      next(error);
    }
  }
};