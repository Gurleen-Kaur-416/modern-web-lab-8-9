import { body } from "express-validator";

export const updateOwnProfileValidator = [
  body("firstName").optional().isString(),
  body("lastName").optional().isString(),
  body("email").optional().isEmail(),
  body("phone").optional().isString(),
  body("city").optional().isString(),
  body("country").optional().isString()
];