"use client";

import { useEffect, useMemo, useState } from "react";
import ProtectedRoute from "@/components/guards/ProtectedRoute";
import RoleGuard from "@/components/guards/RoleGuard";
import PageShell from "@/components/layout/PageShell";
import SectionHeader from "@/components/layout/SectionHeader";
import Alert from "@/components/feedback/Alert";
import StatusBadge from "@/components/tables/StatusBadge";
import { api, ApiRequestError } from "@/lib/api";
import { formatDate } from "@/lib/formatters";
import type { AmendmentRequest } from "@/types/amendment";

function humanizeField(value: string): string {
  const map: Record<string, string> = {
    coverageAmount: "Coverage Amount",
    premiumAmount: "Premium Amount",
    beneficiaryName: "Beneficiary Name",
    vehicleMake: "Vehicle Make",
    vehicleModel: "Vehicle Model",
    propertyAddress: "Property Address"
  };

  return map[value] || value;
}

function summarizeChanges(
  changes: { field: string; currentValue: string; requestedValue: string }[] | undefined
): string {
  if (!changes || changes.length === 0) {
    return "-";
  }

  return changes
    .map(
      (change) =>
        `${humanizeField(change.field)}: ${change.currentValue || "-"} → ${change.requestedValue}`
    )
    .join("; ");
}

export default function AmendmentReviewPage() {
  const [items, setItems] = useState<AmendmentRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [busyId, setBusyId] = useState("");
  const [reviewComments, setReviewComments] = useState<Record<string, string>>({});

  async function loadItems() {
    setLoading(true);
    setError("");

    try {
      const response = await api.get<AmendmentRequest[]>("/amendments");
      setItems(response.data);
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(err.message);
      } else {
        setError("Failed to load amendment requests.");
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadItems();
  }, []);

  const sortedItems = useMemo(() => {
    return [...items].sort((a, b) => {
      const aPending = a.status === "PENDING" ? 0 : 1;
      const bPending = b.status === "PENDING" ? 0 : 1;

      if (aPending !== bPending) {
        return aPending - bPending;
      }

      return String(b.createdAt || "").localeCompare(String(a.createdAt || ""));
    });
  }, [items]);

  async function handleReview(amendmentId: string, status: "APPROVED" | "REJECTED") {
    setBusyId(amendmentId);
    setError("");
    setSuccess("");

    try {
      await api.put(`/amendments/${amendmentId}/review`, {
        status,
        reviewComment: reviewComments[amendmentId] || ""
      });

      setSuccess(`Amendment ${status.toLowerCase()} successfully.`);
      await loadItems();
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(err.message);
      } else {
        setError(`Failed to ${status.toLowerCase()} amendment.`);
      }
    } finally {
      setBusyId("");
    }
  }

  async function handleDelete(amendmentId: string) {
    const confirmed = window.confirm(
      "Are you sure you want to delete this amendment request?"
    );

    if (!confirmed) {
      return;
    }

    setBusyId(amendmentId);
    setError("");
    setSuccess("");

    try {
      await api.delete(`/amendments/${amendmentId}`);
      setSuccess("Amendment deleted successfully.");
      await loadItems();
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(err.message);
      } else {
        setError("Failed to delete amendment.");
      }
    } finally {
      setBusyId("");
    }
  }

  return (
    <ProtectedRoute>
      <RoleGuard allowedRoles={["UNDERWRITER", "ADMIN"]}>
        <PageShell>
          <SectionHeader
            title="Amendment Review"
            subtitle="Underwriting review workspace."
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
            <div className="panel">Loading amendment requests...</div>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Policy Number</th>
                    <th>Customer</th>
                    <th>Requested Changes</th>
                    <th>Reason</th>
                    <th>Created</th>
                    <th>Status</th>
                    <th>Review Comment</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedItems.map((item) => {
                    const isPending = item.status === "PENDING";
                    const isBusy = busyId === item._id;

                    return (
                      <tr key={item._id}>
                        <td>{item.policyNumber || "-"}</td>
                        <td>{item.customerDisplay || "-"}</td>
                        <td>{summarizeChanges(item.changes)}</td>
                        <td>{item.reason}</td>
                        <td>{formatDate(item.createdAt)}</td>
                        <td>
                          <StatusBadge value={item.status} />
                        </td>
                        <td style={{ minWidth: 240 }}>
                          {isPending ? (
                            <textarea
                              value={reviewComments[item._id] || ""}
                              onChange={(e) =>
                                setReviewComments((current) => ({
                                  ...current,
                                  [item._id]: e.target.value
                                }))
                              }
                              placeholder="Optional review comment"
                              style={{ minHeight: 80 }}
                            />
                          ) : (
                            item.reviewComment || "-"
                          )}
                        </td>
                        <td>
                          <div className="actions-row">
                            {isPending ? (
                              <>
                                <button
                                  className="btn btn-primary"
                                  disabled={isBusy}
                                  onClick={() => void handleReview(item._id, "APPROVED")}
                                >
                                  {isBusy ? "Working..." : "Approve"}
                                </button>

                                <button
                                  className="btn btn-secondary"
                                  disabled={isBusy}
                                  onClick={() => void handleReview(item._id, "REJECTED")}
                                >
                                  Reject
                                </button>
                              </>
                            ) : null}

                            <button
                              className="btn btn-secondary"
                              disabled={isBusy}
                              onClick={() => void handleDelete(item._id)}
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}

                  {sortedItems.length === 0 ? (
                    <tr>
                      <td colSpan={8}>No amendment requests found.</td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          )}
        </PageShell>
      </RoleGuard>
    </ProtectedRoute>
  );
}