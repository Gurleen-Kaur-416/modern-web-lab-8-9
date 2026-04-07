import mongoose from "mongoose";
import { amendmentRepository } from "../repositories/amendmentRepository.js";
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

async function getPolicyForAmendment(policyId) {
  if (!mongoose.Types.ObjectId.isValid(policyId)) {
    throw new AppError("Invalid policy id", 400);
  }

  const policy = await policyRepository.findById(policyId);

  if (!policy) {
    throw new AppError("Policy not found", 404);
  }

  return policy;
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

function getUserId(value) {
  if (!value) {
    return "";
  }

  if (typeof value === "object" && value._id) {
    return String(value._id);
  }

  return String(value);
}

function getAmendmentPolicyId(amendment) {
  if (!amendment) {
    return "";
  }

  if (amendment.policy && typeof amendment.policy === "object" && amendment.policy._id) {
    return String(amendment.policy._id);
  }

  if (amendment.policyId) {
    return String(amendment.policyId);
  }

  if (amendment.policy) {
    return String(amendment.policy);
  }

  return "";
}

function castPolicyFieldValue(fieldName, value) {
  if (fieldName === "coverageAmount" || fieldName === "premiumAmount") {
    const numericValue = Number(value);

    if (Number.isNaN(numericValue) || numericValue < 0) {
      throw new AppError(`Invalid value for ${fieldName}`, 422);
    }

    return numericValue;
  }

  return value;
}

function buildPolicyUpdateFromChanges(changes) {
  const allowedFields = new Set([
    "coverageAmount",
    "premiumAmount",
    "beneficiaryName",
    "vehicleMake",
    "vehicleModel",
    "propertyAddress"
  ]);

  const update = {};

  for (const change of changes || []) {
    if (!allowedFields.has(change.field)) {
      throw new AppError("Invalid amendment field", 422);
    }

    update[change.field] = castPolicyFieldValue(
      change.field,
      change.requestedValue
    );
  }

  return update;
}

export const amendmentService = {
  listAll() {
    return amendmentRepository.findAll();
  },

  listForCustomer(customerId) {
    return amendmentRepository.findForCustomer(customerId);
  },

  async getById(id) {
    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new AppError("Invalid amendment id", 400);
    }

    const amendment = await amendmentRepository.findById(id);

    if (!amendment) {
      throw new AppError("Amendment not found", 404);
    }

    return amendment;
  },

  async create(payload, user) {
    const { policyId, changes, reason } = payload;

    if (!isCreator(user)) {
      throw new AppError("Forbidden: insufficient role access", 403);
    }

    if (!policyId) {
      throw new AppError("Policy is required", 422);
    }

    if (!Array.isArray(changes) || changes.length === 0) {
      throw new AppError("At least one amendment change is required", 422);
    }

    if (!reason || !String(reason).trim()) {
      throw new AppError("Reason is required", 422);
    }

    const policy = await getPolicyForAmendment(policyId);

    if (isCustomer(user)) {
      const policyCustomerId = getPolicyCustomerId(policy);

      if (policyCustomerId !== String(user._id)) {
        throw new AppError("Forbidden: ownership validation failed", 403);
      }
    }

    return amendmentRepository.create({
      policy: policy._id,
      changes: changes.map((change) => ({
        field: change.field,
        currentValue: change.currentValue ?? "",
        requestedValue: String(change.requestedValue)
      })),
      reason: String(reason).trim(),
      requestedBy: user._id,
      status: "PENDING"
    });
  },

  async review(amendmentId, payload, user) {
    if (!isReviewer(user)) {
      throw new AppError("Forbidden: insufficient role access", 403);
    }

    const amendment = await this.getById(amendmentId);
    const nextStatus = payload.status;

    if (!["APPROVED", "REJECTED"].includes(nextStatus)) {
      throw new AppError("Invalid review status", 422);
    }

    if (amendment.status !== "PENDING") {
      throw new AppError("Only pending amendments can be reviewed", 422);
    }

    if (nextStatus === "APPROVED") {
      const policyId = getAmendmentPolicyId(amendment);

      if (!policyId) {
        throw new AppError("Amendment policy reference is missing", 500);
      }

      const policyUpdate = buildPolicyUpdateFromChanges(amendment.changes || []);

      if (Object.keys(policyUpdate).length === 0) {
        throw new AppError("No amendment changes found to apply", 422);
      }

      await policyRepository.updateById(policyId, policyUpdate);
    }

    return amendmentRepository.updateById(amendment._id, {
      status: nextStatus,
      reviewComment: payload.reviewComment ?? "",
      reviewedBy: user._id,
      reviewedAt: new Date()
    });
  },

  async delete(amendmentId, user) {
    const amendment = await this.getById(amendmentId);

    if (isCustomer(user)) {
      const requestedById = getUserId(amendment.requestedBy);

      if (requestedById !== String(user._id)) {
        throw new AppError("Forbidden: ownership validation failed", 403);
      }

      return amendmentRepository.deleteById(amendment._id);
    }

    if (isReviewer(user)) {
      return amendmentRepository.deleteById(amendment._id);
    }

    throw new AppError("Forbidden: insufficient role access", 403);
  }
};