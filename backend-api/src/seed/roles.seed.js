import mongoose from "mongoose";
import { connectDatabase } from "../config/db.js";
import { Role } from "../models/Role.js";
import { ROLES } from "../constants/roles.js";
import { PERMISSIONS } from "../constants/permissions.js";

const roles = [
  {
    name: ROLES.CUSTOMER,
    permissions: ["POLICY_VIEW_OWN"]
  },
  {
    name: ROLES.AGENT,
    permissions: [PERMISSIONS.POLICY_CREATE, PERMISSIONS.POLICY_VIEW_ALL]
  },
  {
    name: ROLES.UNDERWRITER,
    permissions: [PERMISSIONS.AMENDMENT_APPROVE, PERMISSIONS.REDUCTION_APPROVE]
  },
  {
    name: ROLES.CLAIMS_ADJUSTER,
    permissions: [PERMISSIONS.CLAIM_APPROVE]
  },
  {
    name: ROLES.CUSTOMER_SERVICE,
    permissions: [PERMISSIONS.POLICY_VIEW_ALL]
  },
  {
    name: ROLES.COMPLIANCE_OFFICER,
    permissions: [PERMISSIONS.USER_READ_ALL]
  },
  {
    name: ROLES.ADMIN,
    permissions: Object.values(PERMISSIONS)
  }
];

async function seedRoles() {
  try {
    await connectDatabase();

    await Role.deleteMany({});
    await Role.insertMany(roles);

    console.log("Roles seeded successfully.");
    await mongoose.disconnect();
  } catch (error) {
    console.error("Failed to seed roles:", error);
    process.exit(1);
  }
}

seedRoles();