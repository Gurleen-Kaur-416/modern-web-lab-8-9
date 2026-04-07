"use client";

import { useMemo } from "react";
import { useAuth } from "./useAuth";

export function useRoleAccess(allowedRoles: string[]) {
  const { user } = useAuth();

  return useMemo(() => {
    if (!user) return false;
    return user.roles.some((role) => allowedRoles.includes(role));
  }, [user, allowedRoles]);
}