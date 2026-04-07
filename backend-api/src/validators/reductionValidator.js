import { body, param } from "express-validator";

export const reductionIdParamValidator = [
  param("reductionId")
    .notEmpty()
    .withMessage("Reduction id is required")
    .isString()
    .withMessage("Reduction id must be a string")
];

export const createReductionValidator = [
  body("policyId")
    .notEmpty()
    .withMessage("Policy is required")
    .isString()
    .withMessage("Policy id must be a string"),

  body("currentCoverage")
    .notEmpty()
    .withMessage("Current coverage is required")
    .isNumeric()
    .withMessage("Current coverage must be numeric"),

  body("requestedCoverage")
    .notEmpty()
    .withMessage("Requested coverage is required")
    .isNumeric()
    .withMessage("Requested coverage must be numeric"),

  body("reason")
    .notEmpty()
    .withMessage("Reason is required")
    .isString()
    .withMessage("Reason must be a string")
];

export const reviewReductionValidator = [
  param("reductionId")
    .notEmpty()
    .withMessage("Reduction id is required")
    .isString()
    .withMessage("Reduction id must be a string"),

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