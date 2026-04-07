"use client";

import { useEffect, useMemo, useState } from "react";
import ProtectedRoute from "@/components/guards/ProtectedRoute";
import RoleGuard from "@/components/guards/RoleGuard";
import PageShell from "@/components/layout/PageShell";
import SectionHeader from "@/components/layout/SectionHeader";
import Alert from "@/components/feedback/Alert";
import StatusBadge from "@/components/tables/StatusBadge";
import { api, ApiRequestError } from "@/lib/api";
import { formatCurrency, formatDate } from "@/lib/formatters";

interface ClaimReviewItem {
  _id: string;
  claimType: string;
  incidentDate: string;
  amount: number;
  description: string;
  createdAt: string;
  status: string;
  reviewComment?: string;
  policy?: {
    _id: string;
    policyNumber?: string;
    customer?: {
      _id: string;
      username?: string;
      fullName?: string;
      profile?: {
        firstName?: string;
        lastName?: string;
        email?: string;
      };
    };
  };
}

function getCustomerDisplay(item: ClaimReviewItem): string {
  const customer = item.policy?.customer;

  if (!customer) {
    return "-";
  }

  if (customer.fullName) {
    return customer.fullName;
  }

  const firstName = customer.profile?.firstName || "";
  const lastName = customer.profile?.lastName || "";
  const fullName = `${firstName} ${lastName}`.trim();

  if (fullName) {
    return fullName;
  }

  return customer.username || "-";
}

function getPolicyNumber(item: ClaimReviewItem): string {
  return item.policy?.policyNumber || "-";
}

export default function ClaimReviewPage() {
  const [items, setItems] = useState<ClaimReviewItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [busyId, setBusyId] = useState("");
  const [comments, setComments] = useState<Record<string, string>>({});

  async function load() {
    setLoading(true);
    setError("");

    try {
      const response = await api.get<ClaimReviewItem[]>("/claims/review");
      setItems(response.data);

      const initialComments: Record<string, string> = {};
      response.data.forEach((item) => {
        initialComments[item._id] = item.reviewComment || "";
      });
      setComments(initialComments);
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(err.message);
      } else {
        setError("Failed to load claim review queue.");
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  const pendingCount = useMemo(
    () => items.filter((item) => item.status === "PENDING").length,
    [items]
  );

  function updateComment(id: string, value: string) {
    setComments((current) => ({
      ...current,
      [id]: value
    }));
  }

  async function handleReview(id: string, status: "APPROVED" | "REJECTED") {
    setBusyId(id);
    setError("");
    setSuccess("");

    try {
      await api.put(`/claims/${id}/review`, {
        status,
        reviewComment: comments[id] || ""
      });

      setSuccess(`Claim ${status.toLowerCase()} successfully.`);
      await load();
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(err.message);
      } else {
        setError("Failed to review claim.");
      }
    } finally {
      setBusyId("");
    }
  }

  async function handleDelete(id: string) {
    const confirmed = window.confirm(
      "Are you sure you want to delete this claim request?"
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
      <RoleGuard allowedRoles={["ADMIN", "CLAIMS_ADJUSTER"]}>
        <PageShell>
          <SectionHeader
            title="Claim Review"
            subtitle={`Claims review workspace. ${pendingCount} pending item${
              pendingCount === 1 ? "" : "s"
            }.`}
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
              <table className="data-table claim-review-table">
                <thead>
                  <tr>
                    <th>Policy Number</th>
                    <th>Customer</th>
                    <th>Claim Type</th>
                    <th>Incident Date</th>
                    <th>Amount</th>
                    <th>Description</th>
                    <th>Created</th>
                    <th>Status</th>
                    <th>Review</th>
                  </tr>
                </thead>

                <tbody>
                  {items.map((item) => {
                    const isPending = item.status === "PENDING";
                    const isBusy = busyId === item._id;

                    return (
                      <tr key={item._id}>
                        <td className="cell-strong">{getPolicyNumber(item)}</td>
                        <td>{getCustomerDisplay(item)}</td>
                        <td>{item.claimType}</td>
                        <td>{formatDate(item.incidentDate)}</td>
                        <td>{formatCurrency(item.amount)}</td>
                        <td className="cell-description">{item.description}</td>
                        <td>{formatDate(item.createdAt)}</td>
                        <td>
                          <StatusBadge value={item.status} />
                        </td>
                        <td>
                          <div className="review-panel">
                            <textarea
                              className="review-textarea"
                              placeholder="Optional review comment"
                              value={comments[item._id] || ""}
                              onChange={(event) =>
                                updateComment(item._id, event.target.value)
                              }
                              disabled={isBusy || !isPending}
                              rows={3}
                            />

                            <div className="review-actions">
                              {isPending ? (
                                <>
                                  <button
                                    className="btn btn-primary"
                                    onClick={() =>
                                      void handleReview(item._id, "APPROVED")
                                    }
                                    disabled={isBusy}
                                  >
                                    {isBusy ? "Working..." : "Approve"}
                                  </button>

                                  <button
                                    className="btn btn-secondary"
                                    onClick={() =>
                                      void handleReview(item._id, "REJECTED")
                                    }
                                    disabled={isBusy}
                                  >
                                    Reject
                                  </button>
                                </>
                              ) : null}

                              <button
                                className="btn btn-secondary"
                                onClick={() => void handleDelete(item._id)}
                                disabled={isBusy}
                              >
                                Delete
                              </button>
                            </div>
                          </div>
                        </td>
                      </tr>
                    );
                  })}

                  {items.length === 0 ? (
                    <tr>
                      <td colSpan={9}>No claims found for review.</td>
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