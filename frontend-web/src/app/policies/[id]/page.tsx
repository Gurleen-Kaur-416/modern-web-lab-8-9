"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import ProtectedRoute from "@/components/guards/ProtectedRoute";
import PageShell from "@/components/layout/PageShell";
import SectionHeader from "@/components/layout/SectionHeader";
import Alert from "@/components/feedback/Alert";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { formatCurrency, formatDate } from "@/lib/formatters";
import type { Policy } from "@/types/policy";

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

function renderPolicySpecificDetails(policy: Policy) {
  if (policy.insuranceType === "LIFE") {
    return (
      <p>
        <strong>Beneficiary:</strong> {policy.beneficiaryName || "-"}
      </p>
    );
  }

  if (policy.insuranceType === "CAR") {
    const vehicleLabel =
      [policy.vehicleMake || "", policy.vehicleModel || ""].join(" ").trim() || "-";

    return (
      <p>
        <strong>Vehicle:</strong> {vehicleLabel}
      </p>
    );
  }

  if (policy.insuranceType === "HOME") {
    return (
      <p>
        <strong>Property Address:</strong> {policy.propertyAddress || "-"}
      </p>
    );
  }

  return (
    <p>
      <strong>Details:</strong> -
    </p>
  );
}

export default function PolicyDetailsPage() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const roleNames = getRoleNames(user?.roles);
  const isAdmin = roleNames.includes("ADMIN");
  const isAgent = roleNames.includes("AGENT");
  const isCustomer = roleNames.includes("CUSTOMER");
  const canCreateAmendment = isCustomer || isAdmin || isAgent;
  const canRequestReduction = isCustomer || isAdmin || isAgent;
  const canSubmitClaim = isCustomer || isAdmin;

  const createdByLabel = useMemo(() => {
    if (!policy) {
      return "-";
    }

    return policy.createdByDisplay || "-";
  }, [policy]);

  useEffect(() => {
    async function load() {
      setLoading(true);
      setError("");

      try {
        const response = await api.get<Policy>(`/policies/${id}`);
        setPolicy(response.data);
      } catch (err: unknown) {
        const message =
          typeof err === "object" &&
          err !== null &&
          "response" in err &&
          typeof (err as { response?: { data?: { message?: string } } }).response?.data?.message === "string"
            ? (err as { response?: { data?: { message?: string } } }).response!.data!.message!
            : "Failed to load policy";

        setError(message);
      } finally {
        setLoading(false);
      }
    }

    void load();
  }, [id]);

  if (loading) {
    return (
      <ProtectedRoute>
        <PageShell>
          <div className="panel">Loading policy...</div>
        </PageShell>
      </ProtectedRoute>
    );
  }

  if (error || !policy) {
    return (
      <ProtectedRoute>
        <PageShell>
          <SectionHeader title="Policy Details" subtitle="Unable to open the selected policy." />
          <Alert variant="error" message={error || "Policy not found"} />
        </PageShell>
      </ProtectedRoute>
    );
  }

  return (
    <ProtectedRoute>
      <PageShell>
        <SectionHeader
          title={`Policy ${policy.policyNumber}`}
          subtitle="Detailed policy record."
        />

        <div className="profile-grid">
          <div className="panel">
            <h3>Core Data</h3>
            <p>
              <strong>Type:</strong> {policy.insuranceType}
            </p>
            <p>
              <strong>Coverage:</strong> {formatCurrency(policy.coverageAmount, policy.currency)}
            </p>
            <p>
              <strong>Premium:</strong> {formatCurrency(policy.premiumAmount, policy.currency)}
            </p>
            <p>
              <strong>Status:</strong> {policy.status}
            </p>
            <p>
              <strong>Effective:</strong> {formatDate(policy.effectiveDate)}
            </p>
            <p>
              <strong>Expiry:</strong> {formatDate(policy.expiryDate)}
            </p>
            <p>
              <strong>Created By:</strong> {createdByLabel}
            </p>
          </div>

          <div className="panel">
            <h3>Policy-Specific Details</h3>
            {renderPolicySpecificDetails(policy)}
          </div>
        </div>

        <div className="actions-row" style={{ marginTop: 20 }}>
          {canCreateAmendment && (
            <Link href={`/policies/amend?policyId=${policy._id}`} className="btn btn-secondary">
              Amend Policy
            </Link>
          )}

          {canRequestReduction && (
            <Link href={`/reductions/create?policyId=${policy._id}`} className="btn btn-secondary">
              Request Reduction
            </Link>
          )}

          {canSubmitClaim && (
            <Link href={`/claims/create?policyId=${policy._id}`} className="btn btn-primary">
              Submit Claim
            </Link>
          )}
        </div>
      </PageShell>
    </ProtectedRoute>
  );
}