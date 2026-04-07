import { Router } from "express"
import { authController } from "../controllers/authController.js"
import { loginValidator } from "../validators/authValidator.js"
import { handleValidation } from "../middleware/validationMiddleware.js"
import { authenticate } from "../middleware/authMiddleware.js"

const router = Router()

// Public routes
router.get("/health", authController.health)
router.post("/login", loginValidator, handleValidation, authController.login)

// Protected – requires a valid, non-blocklisted JWT.
// The token is then added to the blocklist server-side.
router.post("/logout", authenticate, authController.logout)

export default router
