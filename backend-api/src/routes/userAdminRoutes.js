import { Router } from "express";
import { userAdminController } from "../controllers/userAdminController.js";
import { authenticate } from "../middleware/authMiddleware.js";
import { authorizeRoles } from "../middleware/roleMiddleware.js";
import { updateUserStatusValidator } from "../validators/userAdminValidator.js";
import { handleValidation } from "../middleware/validationMiddleware.js";

const router = Router();

router.get("/", authenticate, authorizeRoles("ADMIN"), userAdminController.listUsers);
router.put("/:userId/status", authenticate, authorizeRoles("ADMIN"), updateUserStatusValidator, handleValidation, userAdminController.updateUserStatus);
router.get("/customers", authenticate, authorizeRoles("ADMIN", "AGENT"), userAdminController.listCustomers);

export default router;