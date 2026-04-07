"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import ProtectedRoute from "@/components/guards/ProtectedRoute";
import RoleGuard from "@/components/guards/RoleGuard";
import PageShell from "@/components/layout/PageShell";
import SectionHeader from "@/components/layout/SectionHeader";
import Alert from "@/components/feedback/Alert";
import AmendmentForm from "@/components/forms/AmendmentForm";
import { api } from "@/lib/api";
import { formatCurrency, formatDate } from "@/lib/formatters";
import type { Policy } from "@/types/policy";

function getErrorMessage(error: unknown): string {
  if (
    typeof error === "object" &&
    error !== null &&
    "response" in error &&
    typeof (error as { response?: { data?: { message?: string } } }).response?.data?.message === "string"
  ) {
    return (error as { response?: { data?: { message?: string } } }).response!.data!.message!;
  }

  if (error instanceof Error && error.message) {
    return error.message;
  }

  return "Request failed.";
}

interface AmendmentPayload {
  policyId: string;
  reason: string;
  changes: {
    field: string;
    currentValue: string;
    requestedValue: string;
  }[];
}

export default function PolicyAmendPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const policyId = searchParams.get("policyId") ?? "";

  const [policy, setPolicy] = useState<Policy | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    async function loadPolicy() {
      if (!policyId) {
        setError("Missing policy id.");
        setLoading(false);
        return;
      }

      try {
        const response = await api.get<Policy>(`/policies/${policyId}`);
        setPolicy(response.data);
      } catch (loadError) {
        setError(getErrorMessage(loadError));
      } finally {
        setLoading(false);
      }
    }

    void loadPolicy();
  }, [policyId]);

  async function handleSubmit(payload: AmendmentPayload) {
    setSubmitting(true);
    setError("");

    try {
      await api.post("/amendments", payload);
      router.push("/amendments");
    } catch (submitError) {
      const message = getErrorMessage(submitError);
      setError(message);
      throw new Error(message);
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return (
      <ProtectedRoute>
        <PageShell>
          <div className="panel">Loading policy...</div>
        </PageShell>
      </ProtectedRoute>
    );
  }

  if (error && !policy) {
    return (
      <ProtectedRoute>
        <PageShell>
          <SectionHeader
            title="Amend Policy"
            subtitle="Unable to load policy."
          />
          <Alert variant="error" message={error} />
        </PageShell>
      </ProtectedRoute>
    );
  }

  if (!policy) {
    return (
      <ProtectedRoute>
        <PageShell>
          <SectionHeader
            title="Amend Policy"
            subtitle="Unable to load policy."
          />
          <Alert variant="error" message="Policy not found." />
        </PageShell>
      </ProtectedRoute>
    );
  }

  return (
    <ProtectedRoute>
      <RoleGuard allowedRoles={["CUSTOMER", "ADMIN", "AGENT"]}>
        <PageShell>
          <SectionHeader
            title="Amend Policy"
            subtitle="Submit a policy amendment request."
          />

          <div className="panel" style={{ marginBottom: 20 }}>
            <h3 style={{ marginTop: 0 }}>Policy Summary</h3>
            <p>
              <strong>Policy Number:</strong> {policy.policyNumber}
            </p>
            <p>
              <strong>Type:</strong> {policy.insuranceType}
            </p>
            <p>
              <strong>Status:</strong> {policy.status}
            </p>
            <p>
              <strong>Coverage:</strong> {formatCurrency(policy.coverageAmount, policy.currency)}
            </p>
            <p>
              <strong>Premium:</strong> {formatCurrency(policy.premiumAmount, policy.currency)}
            </p>
            <p>
              <strong>Effective:</strong> {formatDate(policy.effectiveDate)}
            </p>
            <p>
              <strong>Expiry:</strong> {formatDate(policy.expiryDate)}
            </p>
          </div>

          <AmendmentForm
            policy={policy}
            submitting={submitting}
            onSubmit={handleSubmit}
          />

          {error ? (
            <div style={{ marginTop: 16 }}>
              <Alert variant="error" message={error} />
            </div>
          ) : null}

          <div className="actions-row" style={{ marginTop: 20 }}>
            <Link href={`/policies/${policy._id}`} className="btn btn-secondary">
              Back to Policy
            </Link>
          </div>
        </PageShell>
      </RoleGuard>
    </ProtectedRoute>
  );
}