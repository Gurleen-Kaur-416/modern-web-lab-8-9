import mongoose from "mongoose";
import { claimRepository } from "../repositories/claimRepository.js";
import { policyRepository } from "../repositories/policyRepository.js";
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
  return roleNames.includes("CUSTOMER") || roleNames.includes("ADMIN");
}

function isReviewer(user) {
  const roleNames = getRoleNames(user);
  return roleNames.includes("ADMIN") || roleNames.includes("CLAIMS_ADJUSTER");
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

function getClaimPolicyId(claim) {
  if (!claim) {
    return "";
  }

  if (claim.policy && typeof claim.policy === "object" && claim.policy._id) {
    return String(claim.policy._id);
  }

  if (claim.policyId) {
    return String(claim.policyId);
  }

  if (claim.policy) {
    return String(claim.policy);
  }

  return "";
}

async function getPolicyForClaim(policyId) {
  if (!mongoose.Types.ObjectId.isValid(policyId)) {
    throw new AppError("Invalid policy id", 400);
  }

  const policy = await policyRepository.findById(policyId);

  if (!policy) {
    throw new AppError("Policy not found", 404);
  }

  return policy;
}

export const claimService = {
  listAll() {
    return claimRepository.findAll();
  },

  listPending() {
    return claimRepository.findByStatus("PENDING");
  },

  listForCustomer(customerId) {
    return claimRepository.findForCustomer(customerId);
  },

  async getById(id) {
    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new AppError("Invalid claim id", 400);
    }

    const claim = await claimRepository.findById(id);

    if (!claim) {
      throw new AppError("Claim not found", 404);
    }

    return claim;
  },

  async create(payload, user) {
    const { policyId, claimType, incidentDate, amount, description } = payload;

    if (!isCreator(user)) {
      throw new AppError("Forbidden: insufficient role access", 403);
    }

    if (!policyId) {
      throw new AppError("Policy is required", 422);
    }

    if (!claimType) {
      throw new AppError("Claim type is required", 422);
    }

    if (!incidentDate) {
      throw new AppError("Incident date is required", 422);
    }

    if (!description || !String(description).trim()) {
      throw new AppError("Description is required", 422);
    }

    const numericAmount = Number(amount);
    if (Number.isNaN(numericAmount) || numericAmount <= 0) {
      throw new AppError("Claim amount must be a valid positive number", 422);
    }

    const normalizedIncidentDate = new Date(incidentDate);
    if (Number.isNaN(normalizedIncidentDate.getTime())) {
      throw new AppError("Incident date is invalid", 422);
    }

    const policy = await getPolicyForClaim(policyId);

    if (isCustomer(user)) {
      const policyCustomerId = getPolicyCustomerId(policy);
      if (policyCustomerId !== String(user._id || user.id)) {
        throw new AppError("Forbidden: ownership validation failed", 403);
      }
    }

    return claimRepository.create({
      policy: policy._id,
      claimedBy: user._id || user.id,
      claimType,
      incidentDate: normalizedIncidentDate,
      amount: numericAmount,
      description: String(description).trim(),
      status: "PENDING"
    });
  },

  async review(claimId, payload, user) {
    if (!isReviewer(user)) {
      throw new AppError("Forbidden: insufficient role access", 403);
    }

    const claim = await this.getById(claimId);
    const nextStatus = payload.status;

    if (!["APPROVED", "REJECTED"].includes(nextStatus)) {
      throw new AppError("Invalid review status", 422);
    }

    if (claim.status !== "PENDING") {
      throw new AppError("Only pending claims can be reviewed", 422);
    }

    if (nextStatus === "APPROVED") {
      const policyId = getClaimPolicyId(claim);
      if (!policyId) {
        throw new AppError("Claim policy reference is missing", 500);
      }

      const policy = await policyRepository.findById(policyId);
      if (!policy) {
        throw new AppError("Policy not found", 404);
      }

      const approvedClaimsTotal = Number(
        await claimRepository.sumApprovedAmountByPolicyId(policyId)
      );

      const nextApprovedTotal = approvedClaimsTotal + Number(claim.amount);

      if (nextApprovedTotal > Number(policy.coverageAmount)) {
        throw new AppError(
          "Claim cannot be approved because total approved claims would exceed policy coverage",
          422
        );
      }
    }

    return claimRepository.updateById(claim._id, {
      status: nextStatus,
      reviewComment: payload.reviewComment ?? "",
      reviewedBy: user._id || user.id,
      reviewedAt: new Date()
    });
  },

  async delete(claimId, user) {
    const claim = await this.getById(claimId);

    if (isCustomer(user)) {
      const claimedById = getUserId(claim.claimedBy);

      if (claimedById !== String(user._id || user.id)) {
        throw new AppError("Forbidden: ownership validation failed", 403);
      }

      return claimRepository.deleteById(claim._id);
    }

    if (isReviewer(user) || getRoleNames(user).includes("ADMIN")) {
      return claimRepository.deleteById(claim._id);
    }

    throw new AppError("Forbidden: insufficient role access", 403);
  }
};