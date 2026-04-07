import { Router } from "express";
import { keycloakController } from "../controllers/keycloackController.js";

const router = Router();

router.get("/login", keycloakController.login);
router.get("/callback", keycloakController.callback);
router.get("/logout", keycloakController.logout);

export default router;