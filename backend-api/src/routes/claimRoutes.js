import { Router } from "express";
import { claimController } from "../controllers/claimController.js";
import { authenticate } from "../middleware/authMiddleware.js";
import { authorizeRoles } from "../middleware/roleMiddleware.js";
import { handleValidation } from "../middleware/validationMiddleware.js";
import {
  createClaimValidator,
  reviewClaimValidator,
  claimIdParamValidator
} from "../validators/claimValidator.js";

const router = Router();

router.get(
  "/review",
  authenticate,
  authorizeRoles("ADMIN", "CLAIMS_ADJUSTER"),
  claimController.listReviewQueue
);

router.get(
  "/",
  authenticate,
  authorizeRoles("CUSTOMER", "ADMIN", "AGENT", "CLAIMS_ADJUSTER"),
  claimController.listClaims
);

router.get(
  "/:claimId",
  authenticate,
  authorizeRoles("ADMIN", "CLAIMS_ADJUSTER"),
  claimIdParamValidator,
  handleValidation,
  claimController.getClaimById
);

router.post(
  "/",
  authenticate,
  authorizeRoles("CUSTOMER", "ADMIN"),
  createClaimValidator,
  handleValidation,
  claimController.createClaim
);

router.put(
  "/:claimId/review",
  authenticate,
  authorizeRoles("ADMIN", "CLAIMS_ADJUSTER"),
  reviewClaimValidator,
  handleValidation,
  claimController.reviewClaim
);

router.delete(
  "/:claimId",
  authenticate,
  authorizeRoles("CUSTOMER", "ADMIN", "CLAIMS_ADJUSTER"),
  claimIdParamValidator,
  handleValidation,
  claimController.deleteClaim
);

export default router;