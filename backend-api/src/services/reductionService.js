import mongoose from "mongoose";
import { reductionRepository } from "../repositories/reductionRepository.js";
import { policyRepository } from "../repositories/policyRepository.js";
import { claimRepository } from "../repositories/claimRepository.js";
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

function isCustomer(user) {
  return getRoleNames(user).includes("CUSTOMER");
}

function isCreator(user) {
  const roleNames = getRoleNames(user);
  return (
    roleNames.includes("CUSTOMER") ||
    roleNames.includes("ADMIN") ||
    roleNames.includes("AGENT")
  );
}

function isReviewer(user) {
  const roleNames = getRoleNames(user);
  return roleNames.includes("ADMIN") || roleNames.includes("UNDERWRITER");
}

function getUserId(value) {
  if (!value) {
    return "";
  }

  if (typeof value === "object" && value._id) {
    return String(value._id);
  }

  return String(value);
}

function getPolicyCustomerId(policy) {
  if (!policy) {
    return "";
  }

  if (policy.customer && typeof policy.customer === "object" && policy.customer._id) {
    return String(policy.customer._id);
  }

  if (policy.customerId) {
    return String(policy.customerId);
  }

  if (policy.customer) {
    return String(policy.customer);
  }

  return "";
}

function getReductionPolicyId(reduction) {
  if (!reduction) {
    return "";
  }

  if (reduction.policy && typeof reduction.policy === "object" && reduction.policy._id) {
    return String(reduction.policy._id);
  }

  if (reduction.policyId) {
    return String(reduction.policyId);
  }

  if (reduction.policy) {
    return String(reduction.policy);
  }

  return "";
}

async function getPolicyForReduction(policyId) {
  if (!mongoose.Types.ObjectId.isValid(policyId)) {
    throw new AppError("Invalid policy id", 400);
  }

  const policy = await policyRepository.findById(policyId);

  if (!policy) {
    throw new AppError("Policy not found", 404);
  }

  return policy;
}

export const reductionService = {
  listAll() {
    return reductionRepository.findAll();
  },

  listForCustomer(customerId) {
    return reductionRepository.findForCustomer(customerId);
  },

  async getById(id) {
    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new AppError("Invalid reduction id", 400);
    }

    const reduction = await reductionRepository.findById(id);

    if (!reduction) {
      throw new AppError("Reduction request not found", 404);
    }

    return reduction;
  },

  async create(payload, user) {
    const { policyId, currentCoverage, requestedCoverage, reason } = payload;

    if (!isCreator(user)) {
      throw new AppError("Forbidden: insufficient role access", 403);
    }

    if (!policyId) {
      throw new AppError("Policy is required", 422);
    }

    if (!reason || !String(reason).trim()) {
      throw new AppError("Reason is required", 422);
    }

    const numericCurrentCoverage = Number(currentCoverage);
    const numericRequestedCoverage = Number(requestedCoverage);

    if (Number.isNaN(numericCurrentCoverage) || numericCurrentCoverage < 0) {
      throw new AppError("Current coverage must be a valid non-negative number", 422);
    }

    if (Number.isNaN(numericRequestedCoverage) || numericRequestedCoverage < 0) {
      throw new AppError("Requested coverage must be a valid non-negative number", 422);
    }

    if (numericRequestedCoverage >= numericCurrentCoverage) {
      throw new AppError("Requested coverage must be lower than current coverage", 422);
    }

    const policy = await getPolicyForReduction(policyId);

    if (isCustomer(user)) {
      const policyCustomerId = getPolicyCustomerId(policy);

      if (policyCustomerId !== String(user._id)) {
        throw new AppError("Forbidden: ownership validation failed", 403);
      }
    }

    return reductionRepository.create({
      policy: policy._id,
      currentCoverage: numericCurrentCoverage,
      requestedCoverage: numericRequestedCoverage,
      reason: String(reason).trim(),
      requestedBy: user._id,
      status: "PENDING"
    });
  },

  async review(reductionId, payload, user) {
    if (!isReviewer(user)) {
      throw new AppError("Forbidden: insufficient role access", 403);
    }

    const reduction = await this.getById(reductionId);
    const nextStatus = payload.status;

    if (!["APPROVED", "REJECTED"].includes(nextStatus)) {
      throw new AppError("Invalid review status", 422);
    }

    if (reduction.status !== "PENDING") {
      throw new AppError("Only pending reductions can be reviewed", 422);
    }

    if (nextStatus === "APPROVED") {
      const policyId = getReductionPolicyId(reduction);

      if (!policyId) {
        throw new AppError("Reduction policy reference is missing", 500);
      }

      const approvedClaimsTotal = Number(
        await claimRepository.sumApprovedAmountByPolicyId(policyId)
      );

      if (Number(reduction.requestedCoverage) < approvedClaimsTotal) {
        throw new AppError(
          "Reduction cannot be approved because requested coverage is lower than total approved claims",
          422
        );
      }

      await policyRepository.updateById(policyId, {
        coverageAmount: reduction.requestedCoverage
      });
    }

    return reductionRepository.updateById(reduction._id, {
      status: nextStatus,
      reviewComment: payload.reviewComment ?? "",
      reviewedBy: user._id,
      reviewedAt: new Date()
    });
  },

  async delete(reductionId, user) {
    const reduction = await this.getById(reductionId);

    if (isCustomer(user)) {
      const requestedById = getUserId(reduction.requestedBy);

      if (requestedById !== String(user._id)) {
        throw new AppError("Forbidden: ownership validation failed", 403);
      }

      return reductionRepository.deleteById(reduction._id);
    }

    if (isReviewer(user)) {
      return reductionRepository.deleteById(reduction._id);
    }

    throw new AppError("Forbidden: insufficient role access", 403);
  }
};