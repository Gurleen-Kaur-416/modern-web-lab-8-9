import mongoose from "mongoose";

function generatePolicyNumber() {
  const year = new Date().getFullYear();
  const randomPart = Math.floor(100000 + Math.random() * 900000);
  return `POL-${year}-${randomPart}`;
}

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

const policySchema = new mongoose.Schema(
  {
    policyNumber: {
      type: String,
      required: true,
      unique: true,
      default: generatePolicyNumber
    },
    insuranceType: {
      type: String,
      required: true,
      enum: ["LIFE", "CAR", "HOME"]
    },
    customer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    coverageAmount: {
      type: Number,
      required: true,
      min: 0
    },
    premiumAmount: {
      type: Number,
      required: true,
      min: 0
    },
    currency: {
      type: String,
      default: "CAD"
    },
    effectiveDate: {
      type: Date,
      required: true
    },
    expiryDate: {
      type: Date,
      required: true
    },
    status: {
      type: String,
      required: true,
      default: "ACTIVE"
    },
    beneficiaryName: {
      type: String,
      default: null
    },
    vehicleMake: {
      type: String,
      default: null
    },
    vehicleModel: {
      type: String,
      default: null
    },
    propertyAddress: {
      type: String,
      default: null
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null
    }
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform(doc, ret) {
        const originalCustomer = ret.customer;
        const originalCreatedBy = ret.createdBy;

        ret.customerId =
          originalCustomer && typeof originalCustomer === "object" && originalCustomer._id
            ? String(originalCustomer._id)
            : originalCustomer
              ? String(originalCustomer)
              : "";

        ret.createdById =
          originalCreatedBy && typeof originalCreatedBy === "object" && originalCreatedBy._id
            ? String(originalCreatedBy._id)
            : originalCreatedBy
              ? String(originalCreatedBy)
              : "";

        ret.customerDisplay = resolveUserDisplay(originalCustomer);
        ret.createdByDisplay = resolveUserDisplay(originalCreatedBy);

        delete ret.customer;
        delete ret.__v;

        return ret;
      }
    },
    toObject: {
      virtuals: true,
      transform(doc, ret) {
        const originalCustomer = ret.customer;
        const originalCreatedBy = ret.createdBy;

        ret.customerId =
          originalCustomer && typeof originalCustomer === "object" && originalCustomer._id
            ? String(originalCustomer._id)
            : originalCustomer
              ? String(originalCustomer)
              : "";

        ret.createdById =
          originalCreatedBy && typeof originalCreatedBy === "object" && originalCreatedBy._id
            ? String(originalCreatedBy._id)
            : originalCreatedBy
              ? String(originalCreatedBy)
              : "";

        ret.customerDisplay = resolveUserDisplay(originalCustomer);
        ret.createdByDisplay = resolveUserDisplay(originalCreatedBy);

        delete ret.customer;
        delete ret.__v;

        return ret;
      }
    }
  }
);

policySchema.pre("validate", function autoGeneratePolicyNumber(next) {
  if (!this.policyNumber) {
    this.policyNumber = generatePolicyNumber();
  }
  next();
});

export const Policy = mongoose.model("Policy", policySchema);