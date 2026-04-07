import { Router } from "express";
import { amendmentController } from "../controllers/amendmentController.js";
import { authenticate } from "../middleware/authMiddleware.js";
import { authorizeRoles } from "../middleware/roleMiddleware.js";
import { handleValidation } from "../middleware/validationMiddleware.js";
import {
  createAmendmentValidator,
  reviewAmendmentValidator,
  amendmentIdParamValidator
} from "../validators/amendmentValidator.js";

const router = Router();

router.get(
  "/",
  authenticate,
  authorizeRoles("ADMIN", "AGENT", "UNDERWRITER", "CUSTOMER"),
  amendmentController.listAmendments
);

router.get(
  "/:amendmentId",
  authenticate,
  authorizeRoles("CUSTOMER", "ADMIN", "AGENT", "UNDERWRITER"),
  amendmentIdParamValidator,
  handleValidation,
  amendmentController.getAmendmentById
);

router.post(
  "/",
  authenticate,
  authorizeRoles("CUSTOMER", "ADMIN", "AGENT"),
  createAmendmentValidator,
  handleValidation,
  amendmentController.createAmendment
);

router.put(
  "/:amendmentId/review",
  authenticate,
  authorizeRoles("ADMIN", "UNDERWRITER"),
  reviewAmendmentValidator,
  handleValidation,
  amendmentController.reviewAmendment
);

router.delete(
  "/:amendmentId",
  authenticate,
  authorizeRoles("CUSTOMER", "ADMIN", "AGENT", "UNDERWRITER"),
  amendmentIdParamValidator,
  handleValidation,
  amendmentController.deleteAmendment
);

export default router;