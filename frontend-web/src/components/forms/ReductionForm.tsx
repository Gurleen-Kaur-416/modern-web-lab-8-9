"use client";

import { useEffect, useState, type FormEvent } from "react";
import Alert from "@/components/feedback/Alert";

interface ReductionFormState {
  policyId: string;
  currentCoverage: number;
  requestedCoverage: number;
  reason: string;
}

interface ReductionFormProps {
  onSubmit: (payload: ReductionFormState) => Promise<void>;
  initialValues?: Partial<ReductionFormState>;
  policyNumber?: string;
  submitting?: boolean;
}

export default function ReductionForm({
  onSubmit,
  initialValues,
  policyNumber,
  submitting = false
}: ReductionFormProps) {
  const [form, setForm] = useState<ReductionFormState>({
    policyId: initialValues?.policyId ?? "",
    currentCoverage: initialValues?.currentCoverage ?? 0,
    requestedCoverage: initialValues?.requestedCoverage ?? 0,
    reason: initialValues?.reason ?? ""
  });

  const [error, setError] = useState("");

  useEffect(() => {
    setForm({
      policyId: initialValues?.policyId ?? "",
      currentCoverage: initialValues?.currentCoverage ?? 0,
      requestedCoverage: initialValues?.requestedCoverage ?? 0,
      reason: initialValues?.reason ?? ""
    });
  }, [initialValues]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");

    if (!form.policyId) {
      setError("Policy is required.");
      return;
    }

    if (form.requestedCoverage < 0) {
      setError("Requested coverage must be zero or greater.");
      return;
    }

    if (form.requestedCoverage >= form.currentCoverage) {
      setError("Requested coverage must be lower than current coverage.");
      return;
    }

    if (!form.reason.trim()) {
      setError("Reason is required.");
      return;
    }

    try {
      await onSubmit(form);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to submit reduction request.");
    }
  }

  return (
    <form className="form-grid" onSubmit={handleSubmit}>
      <div>
        <label htmlFor="policyNumber">Policy Number</label>
        <input
          id="policyNumber"
          value={policyNumber ?? ""}
          disabled
        />
      </div>

      <div>
        <label htmlFor="currentCoverage">Current Coverage</label>
        <input
          id="currentCoverage"
          type="number"
          value={form.currentCoverage}
          disabled
        />
      </div>

      <div>
        <label htmlFor="requestedCoverage">Requested Coverage</label>
        <input
          id="requestedCoverage"
          type="number"
          min="0"
          value={form.requestedCoverage}
          onChange={(e) =>
            setForm({
              ...form,
              requestedCoverage: Number(e.target.value)
            })
          }
          required
        />
      </div>

      <div className="full-span">
        <label htmlFor="reason">Reason</label>
        <textarea
          id="reason"
          value={form.reason}
          onChange={(e) =>
            setForm({
              ...form,
              reason: e.target.value
            })
          }
          required
        />
      </div>

      {error ? (
        <div className="full-span">
          <Alert variant="error" message={error} />
        </div>
      ) : null}

      <div className="full-span">
        <button className="btn btn-primary" type="submit" disabled={submitting}>
          {submitting ? "Submitting..." : "Submit Reduction Request"}
        </button>
      </div>
    </form>
  );
}