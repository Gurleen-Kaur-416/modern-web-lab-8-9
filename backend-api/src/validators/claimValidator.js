import { body, param } from "express-validator";

export const claimIdParamValidator = [
  param("claimId")
    .notEmpty()
    .withMessage("Claim id is required")
    .isString()
    .withMessage("Claim id must be a string")
];

export const createClaimValidator = [
  body("policyId")
    .notEmpty()
    .withMessage("Policy is required")
    .isString()
    .withMessage("Policy id must be a string"),

  body("claimType")
    .notEmpty()
    .withMessage("Claim type is required")
    .isString()
    .withMessage("Claim type must be a string"),

  body("incidentDate")
    .notEmpty()
    .withMessage("Incident date is required")
    .isISO8601()
    .withMessage("Incident date must be a valid date"),

  body("amount")
    .notEmpty()
    .withMessage("Claim amount is required")
    .isNumeric()
    .withMessage("Claim amount must be numeric"),

  body("description")
    .notEmpty()
    .withMessage("Description is required")
    .isString()
    .withMessage("Description must be a string")
];

export const reviewClaimValidator = [
  param("claimId")
    .notEmpty()
    .withMessage("Claim id is required")
    .isString()
    .withMessage("Claim id must be a string"),

  body("status")
    .notEmpty()
    .withMessage("Status is required")
    .isIn(["APPROVED", "REJECTED"])
    .withMessage("Status must be APPROVED or REJECTED"),

  body("reviewComment")
    .optional({ nullable: true })
    .isString()
    .withMessage("Review comment must be a string")
];