import mongoose from "mongoose";
import { connectDatabase } from "../config/db.js";
import { User } from "../models/User.js";
import { Policy } from "../models/Policy.js";

async function seedPolicies() {
  await connectDatabase();

  const admin = await User.findOne({ username: "admin1" });
  const customer = await User.findOne({ username: "customer1" });

  if (!admin || !customer) {
    throw new Error("Required users not found. Seed users first.");
  }

  await Policy.deleteMany({});

  await Policy.insertMany([
    {
      policyNumber: "LIFE-50001",
      insuranceType: "LIFE",
      customerId: customer._id,
      coverageAmount: 500000,
      premiumAmount: 180,
      effectiveDate: new Date("2026-01-01"),
      expiryDate: new Date("2036-01-01"),
      status: "ACTIVE",
      beneficiaryName: "Sarah Watson",
      createdBy: admin._id
    }
  ]);

  console.log("Policies seeded.");
  await mongoose.disconnect();
}

seedPolicies().catch((error) => {
  console.error(error);
  process.exit(1);
});