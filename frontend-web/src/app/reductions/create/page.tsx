"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import ProtectedRoute from "@/components/guards/ProtectedRoute";
import RoleGuard from "@/components/guards/RoleGuard";
import PageShell from "@/components/layout/PageShell";
import SectionHeader from "@/components/layout/SectionHeader";
import Alert from "@/components/feedback/Alert";
import ReductionForm from "@/components/forms/ReductionForm";
import { api, ApiRequestError } from "@/lib/api";
import { formatCurrency, formatDate } from "@/lib/formatters";

interface Policy {
  _id: string;
  policyNumber: string;
  insuranceType: "LIFE" | "CAR" | "HOME";
  coverageAmount: number;
  premiumAmount: number;
  currency?: string;
  effectiveDate: string;
  expiryDate: string;
  status: string;
}

export default function CreateReductionPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const policyId = searchParams.get("policyId") ?? "";

  const [policy, setPolicy] = useState<Policy | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

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
      } catch (err) {
        if (err instanceof ApiRequestError) {
          setError(err.message);
        } else {
          setError("Failed to load policy.");
        }
      } finally {
        setLoading(false);
      }
    }

    void loadPolicy();
  }, [policyId]);

  async function handleSubmit(payload: {
    policyId: string;
    currentCoverage: number;
    requestedCoverage: number;
    reason: string;
  }) {
    setSubmitting(true);
    setError("");

    try {
      await api.post("/reductions", payload);
      router.push("/reductions");
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(err.message);
      } else {
        setError("Failed to submit reduction request.");
      }
      throw err;
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

  return (
    <ProtectedRoute>
      <RoleGuard allowedRoles={["CUSTOMER", "AGENT", "ADMIN"]}>
        <PageShell>
          <SectionHeader
            title="Create Reduction"
            subtitle="Submit a coverage reduction request."
          />

          {error && !policy ? <Alert variant="error" message={error} /> : null}

          {policy ? (
            <>
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

              {error ? (
                <div style={{ marginBottom: 16 }}>
                  <Alert variant="error" message={error} />
                </div>
              ) : null}

              <ReductionForm
                policyNumber={policy.policyNumber}
                submitting={submitting}
                initialValues={{
                  policyId: policy._id,
                  currentCoverage: policy.coverageAmount,
                  requestedCoverage: 0,
                  reason: ""
                }}
                onSubmit={handleSubmit}
              />

              <div className="actions-row" style={{ marginTop: 20 }}>
                <Link href={`/policies/${policy._id}`} className="btn btn-secondary">
                  Back to Policy
                </Link>
              </div>
            </>
          ) : null}
        </PageShell>
      </RoleGuard>
    </ProtectedRoute>
  );
}