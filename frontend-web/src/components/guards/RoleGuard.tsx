"use client";

import { useEffect, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import Loader from "@/components/feedback/Loader";

interface RoleGuardProps {
  children: ReactNode;
  allowedRoles: string[];
}

export default function RoleGuard({ children, allowedRoles }: RoleGuardProps) {
  const { user, ready } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!ready || !user) return;

    const allowed = user.roles.some((role) => allowedRoles.includes(role));
    if (!allowed) {
      router.push("/unauthorized");
    }
  }, [ready, user, allowedRoles, router]);

  if (!ready || !user) {
    return <Loader label="Checking access..." />;
  }

  const allowed = user.roles.some((role) => allowedRoles.includes(role));
  if (!allowed) {
    return <Loader label="Redirecting..." />;
  }

  return <>{children}</>;
}