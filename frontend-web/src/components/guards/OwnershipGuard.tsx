"use client";

import { useEffect, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import Loader from "@/components/feedback/Loader";

interface OwnershipGuardProps {
  children: ReactNode;
  ownerId?: string | null;
  allowedRoles?: string[];
  redirectTo?: string;
}

export default function OwnershipGuard({
  children,
  ownerId,
  allowedRoles = ["ADMIN"],
  redirectTo = "/unauthorized"
}: OwnershipGuardProps) {
  const { user, ready } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!ready) return;
    if (!user) {
      router.push("/login");
      return;
    }

    const hasAllowedRole = user.roles.some((role) => allowedRoles.includes(role));
    const isOwner = ownerId ? user._id === ownerId : false;

    if (!hasAllowedRole && !isOwner) {
      router.push(redirectTo);
    }
  }, [ready, user, ownerId, allowedRoles, redirectTo, router]);

  if (!ready || !user) {
    return <Loader label="Validating secure access..." />;
  }

  const hasAllowedRole = user.roles.some((role) => allowedRoles.includes(role));
  const isOwner = ownerId ? user._id === ownerId : false;

  if (!hasAllowedRole && !isOwner) {
    return <Loader label="Redirecting..." />;
  }

  return <>{children}</>;
}