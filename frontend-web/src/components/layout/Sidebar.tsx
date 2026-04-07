"use client";

import Link from "next/link";
import {
  Shield,
  LayoutDashboard,
  UserCircle,
  Landmark,
  FileText,
  Users,
  KeyRound
} from "lucide-react";
import { useAuth } from "@/hooks/useAuth";

function getRoleNames(roles: unknown[] | undefined): string[] {
  return (roles || []).map((role) => {
    if (typeof role === "string") {
      return role;
    }

    if (role && typeof role === "object" && "name" in role) {
      return String((role as { name?: string }).name || "");
    }

    return String(role);
  });
}

export default function Sidebar() {
  const { user } = useAuth();
  const roleNames = getRoleNames(user?.roles);

  const isAdmin = roleNames.includes("ADMIN");
  const isCustomer = roleNames.includes("CUSTOMER");
  const isUnderwriter = roleNames.includes("UNDERWRITER");
  const isAdjuster = roleNames.includes("CLAIMS_ADJUSTER");

  const canSeeAmendments = !isAdjuster;
  const canSeeReductions = !isAdjuster;
  const canSeeClaims = isAdmin || isCustomer || isAdjuster;
  const canSeeAmendmentReview = isAdmin || isUnderwriter;
  const canSeeReductionReview = isAdmin || isUnderwriter;
  const canSeeClaimReview = isAdmin || isAdjuster;

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-icon">
          <Shield size={18} />
        </div>
        <div>
          <h1>NorthStar</h1>
          <p>Insurance Platform</p>
        </div>
      </div>

      <nav className="nav-links">
        <Link href="/dashboard">
          <LayoutDashboard size={16} />
          Dashboard
        </Link>

        <Link href="/profile">
          <UserCircle size={16} />
          Profile
        </Link>

        <Link href="/policies">
          <Landmark size={16} />
          Policies
        </Link>

         {canSeeClaims && (
          <Link href="/claims">
            <FileText size={16} />
            Claims
          </Link>
        )}

        {canSeeReductions && (
          <Link href="/reductions">
            <FileText size={16} />
            Reductions
          </Link>
        )}

        {canSeeAmendments && (
          <Link href="/amendments">
            <FileText size={16} />
            Amendments
          </Link>
        )}

        {canSeeAmendmentReview && (
          <Link href="/amendments/review">
            <FileText size={16} />
            Amendment Review
          </Link>
        )}

        {canSeeReductionReview && (
          <Link href="/reductions/review">
            <FileText size={16} />
            Reduction Review
          </Link>
        )}

        {canSeeClaimReview && (
          <Link href="/claims/review">
            <FileText size={16} />
            Claim Review
          </Link>
        )}

        {isAdmin && (
          <>
            <Link href="/admin/users">
              <Users size={16} />
              Admin Users
            </Link>
            <Link href="/admin/roles">
              <KeyRound size={16} />
              Roles
            </Link>
            <Link href="/admin/rbac">
              <KeyRound size={16} />
              RBAC
            </Link>
            <Link href="/admin/account-status">
              <Users size={16} />
              Account Status
            </Link>
          </>
        )}
      </nav>
    </aside>
  );
}