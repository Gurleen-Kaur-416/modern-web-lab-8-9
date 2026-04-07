"use client";

import { useEffect, useMemo, useState, type FormEvent } from "react";
import Alert from "@/components/feedback/Alert";

interface ClaimFormState {
  policyId: string;
  claimType: string;
  incidentDate: string;
  amount: number;
  description: string;
}

interface ClaimFormProps {
  onSubmit: (payload: ClaimFormState) => Promise<void>;
  initialValues?: Partial<ClaimFormState>;
  policyNumber?: string;
  insuranceType?: "LIFE" | "CAR" | "HOME";
  submitting?: boolean;
}

const CLAIM_TYPE_OPTIONS: Record<"LIFE" | "CAR" | "HOME", string[]> = {
  LIFE: [
    "DEATH_BENEFIT",
    "CRITICAL_ILLNESS",
    "DISABILITY",
    "ACCIDENTAL_DEATH",
    "HOSPITALIZATION",
    "GENERAL"
  ],
  CAR: [
    "COLLISION",
    "THEFT",
    "FIRE",
    "GLASS_DAMAGE",
    "LIABILITY",
    "VANDALISM",
    "GENERAL"
  ],
  HOME: [
    "FIRE_DAMAGE",
    "WATER_DAMAGE",
    "THEFT",
    "NATURAL_DISASTER",
    "LIABILITY",
    "PROPERTY_DAMAGE",
    "GENERAL"
  ]
};

function humanizeClaimType(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0) + part.slice(1).toLowerCase())
    .join(" ");
}

export default function ClaimForm({
  onSubmit,
  initialValues,
  policyNumber,
  insuranceType = "LIFE",
  submitting = false
}: ClaimFormProps) {
  const claimTypeOptions = useMemo(
    () => CLAIM_TYPE_OPTIONS[insuranceType] || ["GENERAL"],
    [insuranceType]
  );

  const [form, setForm] = useState<ClaimFormState>({
    policyId: initialValues?.policyId ?? "",
    claimType: initialValues?.claimType ?? claimTypeOptions[0],
    incidentDate: initialValues?.incidentDate ?? "",
    amount: initialValues?.amount ?? 0,
    description: initialValues?.description ?? ""
  });

  const [error, setError] = useState("");

  useEffect(() => {
    setForm({
      policyId: initialValues?.policyId ?? "",
      claimType:
        initialValues?.claimType && claimTypeOptions.includes(initialValues.claimType)
          ? initialValues.claimType
          : claimTypeOptions[0],
      incidentDate: initialValues?.incidentDate ?? "",
      amount: initialValues?.amount ?? 0,
      description: initialValues?.description ?? ""
    });
  }, [initialValues, claimTypeOptions]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");

    if (!form.policyId) {
      setError("Policy is required.");
      return;
    }

    if (!form.claimType.trim()) {
      setError("Claim type is required.");
      return;
    }

    if (!form.incidentDate) {
      setError("Incident date is required.");
      return;
    }

    if (form.amount <= 0) {
      setError("Claim amount must be greater than zero.");
      return;
    }

    if (!form.description.trim()) {
      setError("Description is required.");
      return;
    }

    try {
      await onSubmit(form);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to submit claim.");
    }
  }

  return (
    <form className="form-grid" onSubmit={handleSubmit}>
      <div>
        <label htmlFor="policyNumber">Policy Number</label>
        <input id="policyNumber" value={policyNumber ?? ""} disabled />
      </div>

      <div>
        <label htmlFor="claimType">Claim Type</label>
        <select
          id="claimType"
          className="form-select"
          value={form.claimType}
          onChange={(e) =>
            setForm({
              ...form,
              claimType: e.target.value
            })
          }
          required
        >
          {claimTypeOptions.map((option) => (
            <option key={option} value={option}>
              {humanizeClaimType(option)}
            </option>
          ))}
        </select>
      </div>

      <div>
        <label htmlFor="incidentDate">Incident Date</label>
        <input
          id="incidentDate"
          type="date"
          value={form.incidentDate}
          onChange={(e) =>
            setForm({
              ...form,
              incidentDate: e.target.value
            })
          }
          required
        />
      </div>

      <div>
        <label htmlFor="amount">Claim Amount</label>
        <input
          id="amount"
          type="number"
          min="0.01"
          step="0.01"
          value={form.amount}
          onChange={(e) =>
            setForm({
              ...form,
              amount: Number(e.target.value)
            })
          }
          required
        />
      </div>

      <div className="full-span">
        <label htmlFor="description">Description</label>
        <textarea
          id="description"
          value={form.description}
          onChange={(e) =>
            setForm({
              ...form,
              description: e.target.value
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
          {submitting ? "Submitting..." : "Submit Claim"}
        </button>
      </div>
    </form>
  );
}