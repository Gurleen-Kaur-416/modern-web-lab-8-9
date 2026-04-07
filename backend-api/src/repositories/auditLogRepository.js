import { AuditLog } from "../models/AuditLog.js";

export const auditLogRepository = {
  create(payload) {
    return AuditLog.create(payload);
  }
};