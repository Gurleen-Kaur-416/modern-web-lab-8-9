import mongoose from "mongoose";
import { policyRepository } from "../repositories/policyRepository.js";
import { AppError } from "../utils/appError.js";

const ALLOWED_INSURANCE_TYPES = ["LIFE", "CAR", "HOME"];

function normalizeCreateOrUpdatePayload(payload) {
  const {
    customerId,
    insuranceType,
    coverageAmount,
    premiumAmount,
    effectiveDate,
    expiryDate
  } = payload;

  if (!customerId) {
    throw new AppError("Customer is required", 422);
  }

  if (!mongoose.Types.ObjectId.isValid(customerId)) {
    throw new AppError("Customer id is invalid", 422);
  }

  if (!insuranceType) {
    throw new AppError("Insurance type is required", 422);
  }

  if (!ALLOWED_INSURANCE_TYPES.includes(insuranceType)) {
    throw new AppError("Insurance type must be LIFE, CAR, or HOME", 422);
  }

  const normalizedCoverageAmount = Number(coverageAmount);
  const normalizedPremiumAmount = Number(premiumAmount);

  if (Number.isNaN(normalizedCoverageAmount) || normalizedCoverageAmount < 0) {
    throw new AppError("Coverage amount must be a valid non-negative number", 422);
  }

  if (Number.isNaN(normalizedPremiumAmount) || normalizedPremiumAmount < 0) {
    throw new AppError("Premium amount must be a valid non-negative number", 422);
  }

  const normalizedEffectiveDate = new Date(effectiveDate);
  const normalizedExpiryDate = new Date(expiryDate);

  if (Number.isNaN(normalizedEffectiveDate.getTime())) {
    throw new AppError("Effective date is invalid", 422);
  }

  if (Number.isNaN(normalizedExpiryDate.getTime())) {
    throw new AppError("Expiry date is invalid", 422);
  }

  if (normalizedExpiryDate <= normalizedEffectiveDate) {
    throw new AppError("Expiry date must be later than effective date", 422);
  }

  return {
    insuranceType,
    customer: customerId,
    coverageAmount: normalizedCoverageAmount,
    premiumAmount: normalizedPremiumAmount,
    effectiveDate: normalizedEffectiveDate,
    expiryDate: normalizedExpiryDate
  };
}

function resolveCustomerId(policyLikeObject) {
  if (!policyLikeObject) {
    return "";
  }

  if (policyLikeObject.customerId) {
    return String(policyLikeObject.customerId);
  }

  if (
    policyLikeObject.customer &&
    typeof policyLikeObject.customer === "object" &&
    policyLikeObject.customer._id
  ) {
    return String(policyLikeObject.customer._id);
  }

  if (policyLikeObject.customer) {
    return String(policyLikeObject.customer);
  }

  return "";
}

export const policyService = {
  listAll() {
    return policyRepository.findAll();
  },

  listForCustomer(customerId) {
    return policyRepository.findByCustomerId(customerId);
  },

  async getById(policyId) {
    if (!mongoose.Types.ObjectId.isValid(policyId)) {
      throw new AppError("Invalid policy id", 400);
    }

    const policy = await policyRepository.findById(policyId);

    if (!policy) {
      throw new AppError("Policy not found", 404);
    }

    return policy;
  },

  async create(payload) {
    const normalizedPayload = normalizeCreateOrUpdatePayload(payload);

    return policyRepository.create({
      ...normalizedPayload,
      createdBy: payload.createdBy
    });
  },

  async update(policyId, payload) {
    const existingPolicy = await this.getById(policyId);

    const baseObject =
      typeof existingPolicy.toObject === "function"
        ? existingPolicy.toObject()
        : existingPolicy;

    const customerId = payload.customerId || resolveCustomerId(baseObject);

    const normalizedPayload = normalizeCreateOrUpdatePayload({
      ...baseObject,
      ...payload,
      customerId
    });

    const updatedPolicy = await policyRepository.updateById(
      policyId,
      normalizedPayload
    );

    if (!updatedPolicy) {
      throw new AppError("Policy not found", 404);
    }

    return updatedPolicy;
  }
};