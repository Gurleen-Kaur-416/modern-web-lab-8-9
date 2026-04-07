import { Router } from "express";
import authRoutes from "./authRoutes.js";
import profileRoutes from "./profileRoutes.js";
import userAdminRoutes from "./userAdminRoutes.js";
import rbacRoutes from "./rbacRoutes.js";
import policyRoutes from "./policyRoutes.js";
import amendmentRoutes from "./amendmentRoutes.js";
import reductionRoutes from "./reductionRoutes.js";
import claimRoutes from "./claimRoutes.js";
import dashboardRoutes from "./dashboardRoutes.js";
import keycloakRoutes from "./keycloackRoutes.js";


const router = Router();

router.use("/auth", authRoutes);
router.use("/profile", profileRoutes);
router.use("/admin/users", userAdminRoutes);
router.use("/admin/rbac", rbacRoutes);
router.use("/policies", policyRoutes);
router.use("/amendments", amendmentRoutes);
router.use("/reductions", reductionRoutes);
router.use("/claims", claimRoutes);
router.use("/dashboard", dashboardRoutes);
router.use("/auth/keycloak", keycloakRoutes);

export default router;