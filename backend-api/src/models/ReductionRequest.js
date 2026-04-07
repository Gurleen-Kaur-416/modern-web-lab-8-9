import mongoose from "mongoose";

function resolveUserDisplay(userValue) {
  if (!userValue) {
    return "";
  }

  if (typeof userValue === "string") {
    return userValue;
  }

  if (userValue.profile) {
    const firstName = userValue.profile.firstName || "";
    const lastName = userValue.profile.lastName || "";
    const fullName = `${firstName} ${lastName}`.trim();

    if (fullName) {
      return fullName;
    }

    if (userValue.profile.email) {
      return userValue.profile.email;
    }
  }

  if (userValue.fullName) {
    return userValue.fullName;
  }

  if (userValue.username) {
    return userValue.username;
  }

  if (userValue.email) {
    return userValue.email;
  }

  if (userValue._id) {
    return String(userValue._id);
  }

  return "";
}

function resolvePolicyCustomerDisplay(policyValue) {
  if (!policyValue) {
    return "";
  }

  if (policyValue.customerDisplay) {
    return String(policyValue.customerDisplay);
  }

  if (policyValue.customer) {
    return resolveUserDisplay(policyValue.customer);
  }

  return "";
}

const reductionRequestSchema = new mongoose.Schema(
  {
    policy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Policy",
      required: true
    },
    requestedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    currentCoverage: {
      type: Number,
      required: true,
      min: 0
    },
    requestedCoverage: {
      type: Number,
      required: true,
      min: 0
    },
    reason: {
      type: String,
      required: true
    },
    status: {
      type: String,
      required: true,
      default: "PENDING",
      enum: ["PENDING", "APPROVED", "REJECTED"]
    },
    reviewComment: {
      type: String,
      default: ""
    },
    reviewedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null
    },
    reviewedAt: {
      type: Date,
      default: null
    }
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform(doc, ret) {
        const originalPolicy = ret.policy;
        const originalRequestedBy = ret.requestedBy;
        const originalReviewedBy = ret.reviewedBy;

        ret.policyId =
          originalPolicy && typeof originalPolicy === "object" && originalPolicy._id
            ? String(originalPolicy._id)
            : originalPolicy
              ? String(originalPolicy)
              : "";

        ret.policyNumber =
          originalPolicy && typeof originalPolicy === "object" && originalPolicy.policyNumber
            ? String(originalPolicy.policyNumber)
            : "";

        ret.customerDisplay = resolvePolicyCustomerDisplay(originalPolicy);

        ret.requestedBy =
          originalRequestedBy && typeof originalRequestedBy === "object" && originalRequestedBy._id
            ? String(originalRequestedBy._id)
            : originalRequestedBy
              ? String(originalRequestedBy)
              : "";

        ret.requestedByDisplay = resolveUserDisplay(originalRequestedBy);

        ret.reviewedBy =
          originalReviewedBy && typeof originalReviewedBy === "object" && originalReviewedBy._id
            ? String(originalReviewedBy._id)
            : originalReviewedBy
              ? String(originalReviewedBy)
              : "";

        ret.reviewedByDisplay = resolveUserDisplay(originalReviewedBy);

        delete ret.policy;
        delete ret.__v;

        return ret;
      }
    },
    toObject: {
      virtuals: true,
      transform(doc, ret) {
        const originalPolicy = ret.policy;
        const originalRequestedBy = ret.requestedBy;
        const originalReviewedBy = ret.reviewedBy;

        ret.policyId =
          originalPolicy && typeof originalPolicy === "object" && originalPolicy._id
            ? String(originalPolicy._id)
            : originalPolicy
              ? String(originalPolicy)
              : "";

        ret.policyNumber =
          originalPolicy && typeof originalPolicy === "object" && originalPolicy.policyNumber
            ? String(originalPolicy.policyNumber)
            : "";

        ret.customerDisplay = resolvePolicyCustomerDisplay(originalPolicy);

        ret.requestedBy =
          originalRequestedBy && typeof originalRequestedBy === "object" && originalRequestedBy._id
            ? String(originalRequestedBy._id)
            : originalRequestedBy
              ? String(originalRequestedBy)
              : "";

        ret.requestedByDisplay = resolveUserDisplay(originalRequestedBy);

        ret.reviewedBy =
          originalReviewedBy && typeof originalReviewedBy === "object" && originalReviewedBy._id
            ? String(originalReviewedBy._id)
            : originalReviewedBy
              ? String(originalReviewedBy)
              : "";

        ret.reviewedByDisplay = resolveUserDisplay(originalReviewedBy);

        delete ret.policy;
        delete ret.__v;

        return ret;
      }
    }
  }
);

export const ReductionRequest = mongoose.model(
  "ReductionRequest",
  reductionRequestSchema
);