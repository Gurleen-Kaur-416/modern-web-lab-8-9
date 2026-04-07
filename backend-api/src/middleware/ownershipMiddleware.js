import { Policy } from "../models/Policy.js";
import { errorResponse } from "../utils/apiResponse.js";

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

export async function requirePolicyOwnership(req, res, next) {
  try {
    const policyId = req.params.policyId || req.body.policyId;

    if (!policyId) {
      return errorResponse(res, "Policy identifier is required", 400);
    }

    const policy = await Policy.findById(policyId);

    if (!policy) {
      return errorResponse(res, "Policy not found", 404);
    }

    const roleNames = getRoleNames(req.user);
    const isAdmin = roleNames.includes("ADMIN");
    const isAgent = roleNames.includes("AGENT");
    const isCustomer = roleNames.includes("CUSTOMER");

    const isOwner = String(policy.customer) === String(req.user?._id);

    if (isAdmin || isAgent) {
      req.policy = policy;
      return next();
    }

    if (isCustomer && isOwner) {
      req.policy = policy;
      return next();
    }

    return errorResponse(res, "Forbidden: ownership validation failed", 403);
  } catch (error) {
    return errorResponse(res, "Ownership validation failed", 500);
  }
}