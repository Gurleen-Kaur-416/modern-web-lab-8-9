import { errorResponse } from "../utils/apiResponse.js";

function getRoleNames(user) {
  return (user?.roles || []).map((role) => {
    if (typeof role === "string") {
      return role;
    }

    if (role && typeof role === "object" && role.name) {
      return role.name;
    }

    console.log("DELETE USER ROLES:", req.user?.roles);
    console.log("DELETE ROLE NAMES:", getRoleNames(req.user));

    return String(role);
  });
}

export function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    const roleNames = getRoleNames(req.user);
    const hasAccess = allowedRoles.some((role) => roleNames.includes(role));

    if (!hasAccess) {
      return errorResponse(res, "Forbidden: insufficient role access", 403);
    }

    return next();
  };
}