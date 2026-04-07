import mongoose from "mongoose";
import { ACCOUNT_STATUS_VALUES } from "../constants/accountStatuses.js";

const userProfileSchema = new mongoose.Schema(
  {
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    dateOfBirth: { type: Date },
    email: { type: String, required: true, trim: true, lowercase: true },
    phone: { type: String, trim: true },
    addressLine1: { type: String, trim: true },
    addressLine2: { type: String, trim: true },
    city: { type: String, trim: true },
    province: { type: String, trim: true },
    postalCode: { type: String, trim: true },
    country: { type: String, trim: true },
    customerNumber: { type: String, trim: true },
    employeeNumber: { type: String, trim: true },
    userType: { type: String, required: true },
    preferredContactMethod: { type: String, trim: true },
    emergencyContactName: { type: String, trim: true },
    emergencyContactPhone: { type: String, trim: true },
    department: { type: String, trim: true },
    jobTitle: { type: String, trim: true },
    supervisorName: { type: String, trim: true },
    internalAccessStatus: { type: String, trim: true }
  },
  { _id: false }
);

const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true, trim: true },
    passwordHash: { type: String, required: true },
    roles: [{ type: mongoose.Schema.Types.ObjectId, ref: "Role", required: true }],
    accountStatus: {
      type: String,
      required: true,
      enum: ACCOUNT_STATUS_VALUES,
      default: "ACTIVE"
    },
    profile: { type: userProfileSchema, required: true },
    lastLoginAt: { type: Date }
  },
  { timestamps: true }
);

export const User = mongoose.model("User", userSchema);