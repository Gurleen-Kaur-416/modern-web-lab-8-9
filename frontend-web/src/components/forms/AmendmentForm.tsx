"use client";

import { useState, type FormEvent } from "react";
import Alert from "@/components/feedback/Alert";
import type { Policy } from "@/types/policy";

interface AmendmentChangePayload {
  field: string;
  currentValue: string;
  requestedValue: string;
}

interface AmendmentPayload {
  policyId: string;
  reason: string;
  changes: AmendmentChangePayload[];
}

interface Props {
  policy: Policy;
  onSubmit: (payload: AmendmentPayload) => Promise<void>;
  submitting?: boolean;
}

type AmendmentField =
  | "coverageAmount"
  | "premiumAmount"
  | "beneficiaryName"
  | "vehicleMake"
  | "vehicleModel"
  | "propertyAddress";

export default function AmendmentForm({
  policy,
  onSubmit,
  submitting = false
}: Props) {
  const [error, setError] = useState("");
  const [reason, setReason] = useState("");

  const [form, setForm] = useState({
    coverageAmount: String(policy.coverageAmount ?? ""),
    premiumAmount: String(policy.premiumAmount ?? ""),
    beneficiaryName: policy.beneficiaryName ?? "",
    vehicleMake: policy.vehicleMake ?? "",
    vehicleModel: policy.vehicleModel ?? "",
    propertyAddress: policy.propertyAddress ?? ""
  });

  function update(field: AmendmentField, value: string) {
    setForm((current) => ({
      ...current,
      [field]: value
    }));
  }

  const rows: Array<{
    key: AmendmentField;
    label: string;
    currentValue: string;
    type?: "text" | "number";
  }> = [
    {
      key: "coverageAmount",
      label: "Coverage Amount",
      currentValue: String(policy.coverageAmount ?? ""),
      type: "number"
    },
    {
      key: "premiumAmount",
      label: "Premium Amount",
      currentValue: String(policy.premiumAmount ?? ""),
      type: "number"
    }
  ];

  if (policy.insuranceType === "LIFE") {
    rows.push({
      key: "beneficiaryName",
      label: "Beneficiary Name",
      currentValue: policy.beneficiaryName ?? "-",
      type: "text"
    });
  }

  if (policy.insuranceType === "CAR") {
    rows.push(
      {
        key: "vehicleMake",
        label: "Vehicle Make",
        currentValue: policy.vehicleMake ?? "-",
        type: "text"
      },
      {
        key: "vehicleModel",
        label: "Vehicle Model",
        currentValue: policy.vehicleModel ?? "-",
        type: "text"
      }
    );
  }

  if (policy.insuranceType === "HOME") {
    rows.push({
      key: "propertyAddress",
      label: "Property Address",
      currentValue: policy.propertyAddress ?? "-",
      type: "text"
    });
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");

    if (!reason.trim()) {
      setError("Reason is required.");
      return;
    }

    const changes = rows
      .map((row) => {
        const current = row.currentValue === "-" ? "" : row.currentValue;
        const requested = form[row.key].trim();

        if (current === requested) {
          return null;
        }

        return {
          field: row.key,
          currentValue: current,
          requestedValue: requested
        };
      })
      .filter(Boolean) as AmendmentChangePayload[];

    if (changes.length === 0) {
      setError("Please change at least one field before submitting.");
      return;
    }

    try {
      await onSubmit({
        policyId: policy._id,
        reason: reason.trim(),
        changes
      });
    } catch (submitError) {
      setError(
        submitError instanceof Error
          ? submitError.message
          : "Failed to submit amendment request."
      );
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <div className="panel" style={{ marginBottom: 20 }}>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr 1fr",
            gap: 16,
            alignItems: "center"
          }}
        >
          <div>
            <strong>Field</strong>
          </div>
          <div>
            <strong>Current Value</strong>
          </div>
          <div>
            <strong>New Value</strong>
          </div>

          {rows.map((row) => (
            <div key={row.key} style={{ display: "contents" }}>
              <div>{row.label}</div>
              <div>
                <input value={row.currentValue} disabled />
              </div>
              <div>
                <input
                  type={row.type ?? "text"}
                  value={form[row.key]}
                  onChange={(e) => update(row.key, e.target.value)}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="panel" style={{ marginBottom: 20 }}>
        <label htmlFor="reason">Reason for Amendment Request</label>
        <textarea
          id="reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Explain why the amendment is required."
          required
        />
      </div>

      {error ? (
        <div style={{ marginBottom: 16 }}>
          <Alert variant="error" message={error} />
        </div>
      ) : null}

      <button type="submit" className="btn btn-primary" disabled={submitting}>
        {submitting ? "Submitting..." : "Submit Amendment"}
      </button>
    </form>
  );
}