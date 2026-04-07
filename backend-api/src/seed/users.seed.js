import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import { connectDatabase } from "../config/db.js";
import { User } from "../models/User.js";
import { Role } from "../models/Role.js";
import { ROLES } from "../constants/roles.js";

async function seedUsers() {
  try {
    await connectDatabase();

    const [
      adminRole,
      customerRole,
      agentRole,
      underwriterRole,
      claimsAdjusterRole
    ] = await Promise.all([
      Role.findOne({ name: ROLES.ADMIN }),
      Role.findOne({ name: ROLES.CUSTOMER }),
      Role.findOne({ name: ROLES.AGENT }),
      Role.findOne({ name: ROLES.UNDERWRITER }),
      Role.findOne({ name: ROLES.CLAIMS_ADJUSTER })
    ]);

    if (!adminRole || !customerRole || !agentRole || !underwriterRole || !claimsAdjusterRole) {
      throw new Error("Required roles not found. Seed roles first.");
    }

    await User.deleteMany({});

    const passwordHash = await bcrypt.hash("Password123!", 10);

    await User.insertMany([
      {
        username: "admin1",
        passwordHash,
        roles: [adminRole._id],
        accountStatus: "ACTIVE",
        profile: {
          firstName: "Victoria",
          lastName: "Clark",
          email: "admin1@example.com",
          userType: "INTERNAL",
          department: "Administration",
          jobTitle: "Platform Administrator"
        }
      },
      {
        username: "customer1",
        passwordHash,
        roles: [customerRole._id],
        accountStatus: "ACTIVE",
        profile: {
          firstName: "Emma",
          lastName: "Watson",
          email: "customer1@example.com",
          userType: "CUSTOMER",
          city: "Toronto",
          country: "Canada"
        }
      },
      {
        username: "agent1",
        passwordHash,
        roles: [agentRole._id],
        accountStatus: "ACTIVE",
        profile: {
          firstName: "Daniel",
          lastName: "Foster",
          email: "agent1@example.com",
          userType: "INTERNAL",
          department: "Sales",
          jobTitle: "Insurance Agent"
        }
      },
      {
        username: "underwriter1",
        passwordHash,
        roles: [underwriterRole._id],
        accountStatus: "ACTIVE",
        profile: {
          firstName: "Sophia",
          lastName: "Lee",
          email: "underwriter1@example.com",
          userType: "INTERNAL",
          department: "Underwriting",
          jobTitle: "Senior Underwriter"
        }
      },
      {
        username: "adjuster1",
        passwordHash,
        roles: [claimsAdjusterRole._id],
        accountStatus: "ACTIVE",
        profile: {
          firstName: "Olivia",
          lastName: "Brown",
          email: "adjuster1@example.com",
          userType: "INTERNAL",
          department: "Claims",
          jobTitle: "Claims Adjuster"
        }
      }
    ]);

    console.log("Users seeded successfully.");
    await mongoose.disconnect();
  } catch (error) {
    console.error("Failed to seed users:", error);
    process.exit(1);
  }
}

seedUsers();