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
import type { Claim } from "@/types/claims";

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

export default function ClaimsPage() {
  const { user } = useAuth();
  const roleNames = getRoleNames(user?.roles);
  const isCustomer = roleNames.includes("CUSTOMER");

  const [items, setItems] = useState<Claim[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [busyId, setBusyId] = useState("");

  async function load() {
    setLoading(true);
    setError("");

    try {
      const response = await api.get<Claim[]>("/claims");
      setItems(response.data);
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(err.message);
      } else {
        setError("Failed to load claims.");
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
      "Are you sure you want to delete this claim?"
    );

    if (!confirmed) {
      return;
    }

    setBusyId(id);
    setError("");
    setSuccess("");

    try {
      await api.delete(`/claims/${id}`);
      setSuccess("Claim deleted successfully.");
      await load();
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(err.message);
      } else {
        setError("Failed to delete claim.");
      }
    } finally {
      setBusyId("");
    }
  }

  return (
    <ProtectedRoute>
      <PageShell>
        <SectionHeader
          title="Claims"
          subtitle={
            isCustomer
              ? "Your submitted claims."
              : "Submitted claims overview."
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
          <div className="panel">Loading claims...</div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Policy Number</th>
                  {!isCustomer ? <th>Customer</th> : null}
                  <th>Claim Type</th>
                  <th>Incident Date</th>
                  <th>Amount</th>
                  <th>Description</th>
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
                    <td>{item.claimType}</td>
                    <td>{formatDate(item.incidentDate)}</td>
                    <td>{formatCurrency(item.amount)}</td>
                    <td>{item.description}</td>
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
                    <td colSpan={isCustomer ? 8 : 9}>No claims found.</td>
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