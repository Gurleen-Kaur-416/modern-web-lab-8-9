import { body, param } from "express-validator";

export const amendmentIdParamValidator = [
  param("amendmentId")
    .notEmpty()
    .withMessage("Amendment id is required")
    .isString()
    .withMessage("Amendment id must be a string")
];

export const createAmendmentValidator = [
  body("policyId")
    .notEmpty()
    .withMessage("Policy is required")
    .isString()
    .withMessage("Policy id must be a string"),

  body("reason")
    .notEmpty()
    .withMessage("Reason is required")
    .isString()
    .withMessage("Reason must be a string"),

  body("changes")
    .isArray({ min: 1 })
    .withMessage("At least one amendment change is required"),

  body("changes.*.field")
    .notEmpty()
    .withMessage("Change field is required")
    .isIn([
      "coverageAmount",
      "premiumAmount",
      "beneficiaryName",
      "vehicleMake",
      "vehicleModel",
      "propertyAddress"
    ])
    .withMessage("Invalid amendment field"),

  body("changes.*.currentValue")
    .optional({ nullable: true })
    .isString()
    .withMessage("Current value must be a string"),

  body("changes.*.requestedValue")
    .notEmpty()
    .withMessage("Requested value is required")
    .isString()
    .withMessage("Requested value must be a string")
];

export const reviewAmendmentValidator = [
  param("amendmentId")
    .notEmpty()
    .withMessage("Amendment id is required")
    .isString()
    .withMessage("Amendment id must be a string"),

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