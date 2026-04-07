export function authorizePermissions(...allowedPermissions) {
  return (req, res, next) => {
    const currentPermissions = req.auth?.permissions || [];
    const hasPermission = currentPermissions.some((permission) => allowedPermissions.includes(permission));

    if (!hasPermission) {
      return res.status(403).json({ success: false, message: "Forbidden" });
    }

    next();
  };
}