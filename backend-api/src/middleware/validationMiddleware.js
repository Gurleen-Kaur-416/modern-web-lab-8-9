import { validationResult } from "express-validator";
import { errorResponse } from "../utils/apiResponse.js";

export function handleValidation(req, res, next) {
  const result = validationResult(req);

  if (!result.isEmpty()) {
    return errorResponse(res, "Validation failed", 422, result.array());
  }

  next();
}

export function validateRequest(req, res, next) {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: "Validation failed",
      errors: errors.array()
    });
  }

  next();
}