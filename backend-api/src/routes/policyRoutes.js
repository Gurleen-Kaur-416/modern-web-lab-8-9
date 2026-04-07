import { Router } from "express";
import { policyController } from "../controllers/policyController.js";
import { authenticate } from "../middleware/authMiddleware.js";
import { authorizeRoles } from "../middleware/roleMiddleware.js";
import {
  createPolicyValidator,
  updatePolicyValidator,
  policyIdParamValidator
} from "../validators/policyValidator.js";
import { handleValidation } from "../middleware/validationMiddleware.js";

const router = Router();

router.get("/", authenticate, policyController.listPolicies);

router.get(
  "/:policyId",
  authenticate,
  policyIdParamValidator,
  handleValidation,
  policyController.getPolicyById
);

router.post(
  "/",
  authenticate,
  authorizeRoles("AGENT", "ADMIN"),
  createPolicyValidator,
  handleValidation,
  policyController.createPolicy
);

router.put(
  "/:policyId",
  authenticate,
  authorizeRoles("AGENT", "ADMIN"),
  updatePolicyValidator,
  handleValidation,
  policyController.updatePolicy
);

export default router;