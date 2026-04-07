import { body, param } from "express-validator";

export const createPolicyValidator = [
  body("insuranceType")
    .notEmpty()
    .withMessage("Insurance type is required")
    .isIn(["LIFE", "CAR", "HOME"])
    .withMessage("Insurance type must be LIFE, CAR, or HOME"),

  body("customerId")
    .notEmpty()
    .withMessage("Customer is required")
    .isString()
    .withMessage("Customer id must be a string"),

  body("coverageAmount")
    .notEmpty()
    .withMessage("Coverage amount is required")
    .isNumeric()
    .withMessage("Coverage amount must be numeric"),

  body("premiumAmount")
    .notEmpty()
    .withMessage("Premium amount is required")
    .isNumeric()
    .withMessage("Premium amount must be numeric"),

  body("effectiveDate")
    .notEmpty()
    .withMessage("Effective date is required")
    .isISO8601()
    .withMessage("Effective date must be a valid date"),

  body("expiryDate")
    .notEmpty()
    .withMessage("Expiry date is required")
    .isISO8601()
    .withMessage("Expiry date must be a valid date")
];

export const updatePolicyValidator = [
  param("policyId")
    .notEmpty()
    .withMessage("Policy id is required")
    .isString()
    .withMessage("Policy id must be a string"),

  body("insuranceType")
    .notEmpty()
    .withMessage("Insurance type is required")
    .isIn(["LIFE", "CAR", "HOME"])
    .withMessage("Insurance type must be LIFE, CAR, or HOME"),

  body("customerId")
    .notEmpty()
    .withMessage("Customer is required")
    .isString()
    .withMessage("Customer id must be a string"),

  body("coverageAmount")
    .notEmpty()
    .withMessage("Coverage amount is required")
    .isNumeric()
    .withMessage("Coverage amount must be numeric"),

  body("premiumAmount")
    .notEmpty()
    .withMessage("Premium amount is required")
    .isNumeric()
    .withMessage("Premium amount must be numeric"),

  body("effectiveDate")
    .notEmpty()
    .withMessage("Effective date is required")
    .isISO8601()
    .withMessage("Effective date must be a valid date"),

  body("expiryDate")
    .notEmpty()
    .withMessage("Expiry date is required")
    .isISO8601()
    .withMessage("Expiry date must be a valid date")
];

export const policyIdParamValidator = [
  param("policyId")
    .notEmpty()
    .withMessage("Policy id is required")
    .isString()
    .withMessage("Policy id must be a string")
];