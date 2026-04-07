"use client";

import { useEffect, useState } from "react";
import ProtectedRoute from "@/components/guards/ProtectedRoute";
import PageShell from "@/components/layout/PageShell";
import SectionHeader from "@/components/layout/SectionHeader";
import Alert from "@/components/feedback/Alert";
import StatusBadge from "@/components/tables/StatusBadge";
import { api, ApiRequestError } from "@/lib/api";
import { formatCurrency, formatDate } from "@/lib/formatters";
import { useAuth } from "@/hooks/useAuth";
import type { ReductionRequest } from "@/types/reduction";

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

export default function ReductionsPage() {
  const { user } = useAuth();
  const roleNames = getRoleNames(user?.roles);
  const isCustomer = roleNames.includes("CUSTOMER");

  const [items, setItems] = useState<ReductionRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [busyId, setBusyId] = useState("");

  async function load() {
    setLoading(true);
    setError("");

    try {
      const response = await api.get<ReductionRequest[]>("/reductions");
      setItems(response.data);
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(err.message);
      } else {
        setError("Failed to load reductions.");
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function handleDelete(id: string) {
    const confirmed = window.confirm(
      "Are you sure you want to delete this reduction request?"
    );

    if (!confirmed) {
      return;
    }

    setBusyId(id);
    setError("");
    setSuccess("");

    try {
      await api.delete(`/reductions/${id}`);
      setSuccess("Reduction deleted successfully.");
      await load();
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(err.message);
      } else {
        setError("Failed to delete reduction.");
      }
    } finally {
      setBusyId("");
    }
  }

  return (
    <ProtectedRoute>
      <PageShell>
        <SectionHeader
          title="Reductions"
          subtitle={
            isCustomer
              ? "Your submitted reduction requests."
              : "Submitted reduction requests overview."
          }
        />

        {error ? (
          <div style={{ marginBottom: 16 }}>
            <Alert variant="error" message={error} />
          </div>
        ) : null}

        {success ? (
          <div style={{ marginBottom: 16 }}>
            <Alert variant="success" message={success} />
          </div>
        ) : null}

        {loading ? (
          <div className="panel">Loading reductions...</div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Policy Number</th>
                  {!isCustomer ? <th>Customer</th> : null}
                  <th>Current Coverage</th>
                  <th>Requested Coverage</th>
                  <th>Reason</th>
                  <th>Created</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>

              <tbody>
                {items.map((item) => (
                  <tr key={item._id}>
                    <td>{item.policyNumber || "-"}</td>
                    {!isCustomer ? <td>{item.customerDisplay || "-"}</td> : null}
                    <td>{formatCurrency(item.currentCoverage)}</td>
                    <td>{formatCurrency(item.requestedCoverage)}</td>
                    <td>{item.reason}</td>
                    <td>{formatDate(item.createdAt)}</td>
                    <td>
                      <StatusBadge value={item.status} />
                    </td>
                    <td>
                      <div className="actions-row">
                        <button
                          className="btn btn-secondary"
                          disabled={busyId === item._id}
                          onClick={() => void handleDelete(item._id)}
                        >
                          {busyId === item._id ? "Deleting..." : "Delete"}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}

                {items.length === 0 ? (
                  <tr>
                    <td colSpan={isCustomer ? 7 : 8}>No reduction requests found.</td>
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