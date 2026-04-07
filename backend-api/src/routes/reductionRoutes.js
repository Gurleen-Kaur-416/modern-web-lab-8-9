import { Router } from "express";
import { reductionController } from "../controllers/reductionController.js";
import { authenticate } from "../middleware/authMiddleware.js";
import { authorizeRoles } from "../middleware/roleMiddleware.js";
import { handleValidation } from "../middleware/validationMiddleware.js";
import {
  createReductionValidator,
  reviewReductionValidator,
  reductionIdParamValidator
} from "../validators/reductionValidator.js";

const router = Router();

router.get(
  "/",
  authenticate,
  authorizeRoles("CUSTOMER", "ADMIN", "AGENT", "UNDERWRITER"),
  reductionController.listReductions
);

router.get(
  "/:reductionId",
  authenticate,
  authorizeRoles("ADMIN", "UNDERWRITER"),
  reductionIdParamValidator,
  handleValidation,
  reductionController.getReductionById
);

router.post(
  "/",
  authenticate,
  authorizeRoles("CUSTOMER", "ADMIN", "AGENT"),
  createReductionValidator,
  handleValidation,
  reductionController.createReduction
);

router.put(
  "/:reductionId/review",
  authenticate,
  authorizeRoles("ADMIN", "UNDERWRITER"),
  reviewReductionValidator,
  handleValidation,
  reductionController.reviewReduction
);

router.delete(
  "/:reductionId",
  authenticate,
  authorizeRoles("CUSTOMER", "ADMIN", "UNDERWRITER"),
  reductionIdParamValidator,
  handleValidation,
  reductionController.deleteReduction
);

export default router;