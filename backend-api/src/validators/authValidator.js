import { body } from "express-validator";

export const loginValidator = [
  body("username").trim().notEmpty().withMessage("Username is required"),
  body("password").notEmpty().withMessage("Password is required")
];