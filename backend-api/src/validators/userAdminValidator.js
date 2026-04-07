import { body } from "express-validator";

export const updateUserStatusValidator = [
  body("accountStatus").notEmpty().isString()
];