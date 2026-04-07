"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import ProtectedRoute from "@/components/guards/ProtectedRoute";
import PageShell from "@/components/layout/PageShell";
import SectionHeader from "@/components/layout/SectionHeader";
import Alert from "@/components/feedback/Alert";
import { api, ApiRequestError } from "@/lib/api";
import { formatCurrency, formatDate } from "@/lib/formatters";
import { useAuth } from "@/hooks/useAuth";
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

export default function PoliciesPage() {
  const { user } = useAuth();
  const roleNames = useMemo(() => getRoleNames(user?.roles), [user?.roles]);

  const isCustomer = roleNames.includes("CUSTOMER");
  const isAdmin = roleNames.includes("ADMIN");
  const isAgent = roleNames.includes("AGENT");

  const canCreatePolicy = isAdmin || isAgent;
  const canCreateAmendment = isCustomer || isAdmin || isAgent;
  const canCreateReduction = isCustomer || isAdmin || isAgent;
  const canCreateClaim = isCustomer || isAdmin;

  const [items, setItems] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadPolicies() {
      setLoading(true);
      setError("");

      try {
        const response = await api.get<Policy[]>("/policies");
        setItems(response.data);
      } catch (err) {
        if (err instanceof ApiRequestError) {
          setError(err.message);
        } else {
          setError("Failed to load policies.");
        }
      } finally {
        setLoading(false);
      }
    }

    void loadPolicies();
  }, []);

  return (
    <ProtectedRoute>
      <PageShell>
        <SectionHeader
          title="Policies"
          subtitle="Life, Car, and Home insurance policies with role-based actions."
          action={
            canCreatePolicy ? (
              <Link href="/policies/create" className="btn btn-primary">
                Create Policy
              </Link>
            ) : null
          }
        />

        {error ? (
          <div style={{ marginBottom: 16 }}>
            <Alert variant="error" message={error} />
          </div>
        ) : null}

        {loading ? (
          <div className="panel">Loading policies...</div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Policy #</th>
                  <th>Type</th>
                  <th>Coverage</th>
                  <th>Premium</th>
                  <th>Effective</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>

              <tbody>
                {items.map((policy) => (
                  <tr key={policy._id}>
                    <td>{policy.policyNumber}</td>
                    <td>{policy.insuranceType}</td>
                    <td>{formatCurrency(policy.coverageAmount, policy.currency)}</td>
                    <td>{formatCurrency(policy.premiumAmount, policy.currency)}</td>
                    <td>{formatDate(policy.effectiveDate)}</td>
                    <td>{policy.status}</td>
                    <td>
                      <div className="actions-row">
                        <Link href={`/policies/${policy._id}`} className="btn btn-secondary">
                          View
                        </Link>

                        {canCreateAmendment ? (
                          <Link
                            href={`/policies/amend?policyId=${policy._id}`}
                            className="btn btn-secondary"
                          >
                            Amend
                          </Link>
                        ) : null}

                        {canCreateReduction ? (
                          <Link
                            href={`/reductions/create?policyId=${policy._id}`}
                            className="btn btn-secondary"
                          >
                            Reduce
                          </Link>
                        ) : null}

                        {canCreateClaim ? (
                          <Link
                            href={`/claims/create?policyId=${policy._id}`}
                            className="btn btn-primary"
                          >
                            Claim
                          </Link>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}

                {items.length === 0 ? (
                  <tr>
                    <td colSpan={7}>No policies found.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        )}
      </PageShell>
    </ProtectedRoute>
  );
}