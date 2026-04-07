"use client";

import { useEffect, useMemo, useState, type FormEvent } from "react";
import Alert from "@/components/feedback/Alert";

export interface PolicyCustomerOption {
  _id: string;
  username: string;
  profile?: {
    firstName?: string;
    lastName?: string;
    email?: string;
  };
}

export interface PolicyFormValues {
  insuranceType: string;
  customerId: string;
  coverageAmount: string;
  premiumAmount: string;
  effectiveDate: string;
  expiryDate: string;
}

interface PolicyFormProps {
  onSubmit: (payload: PolicyFormValues) => Promise<void>;
  customers?: PolicyCustomerOption[];
  initialValues?: Partial<PolicyFormValues>;
  submitLabel?: string;
  loadingCustomers?: boolean;
}

const defaultValues: PolicyFormValues = {
  insuranceType: "LIFE",
  customerId: "",
  coverageAmount: "",
  premiumAmount: "",
  effectiveDate: "",
  expiryDate: ""
};

export default function PolicyForm({
  onSubmit,
  customers = [],
  initialValues,
  submitLabel = "Create Policy",
  loadingCustomers = false
}: PolicyFormProps) {
  const resolvedInitialValues = useMemo(
    () => ({ ...defaultValues, ...initialValues }),
    [initialValues]
  );

  const [form, setForm] = useState<PolicyFormValues>(resolvedInitialValues);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    setForm(resolvedInitialValues);
  }, [resolvedInitialValues]);

  function updateField<K extends keyof PolicyFormValues>(
    field: K,
    value: PolicyFormValues[K]
  ) {
    setForm((current) => ({ ...current, [field]: value }));
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError("");

    try {
      await onSubmit(form);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save policy");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="form-grid" onSubmit={handleSubmit}>
      <div>
        <label htmlFor="insuranceType">Insurance Type</label>
        <select
          id="insuranceType"
          className="form-select"
          value={form.insuranceType}
          onChange={(e) => updateField("insuranceType", e.target.value)}
          required
        >
          <option value="LIFE">Life</option>
          <option value="CAR">Car</option>
          <option value="HOME">Home</option>
        </select>
      </div>

      <div className="full-span">
        <label htmlFor="customerId">Customer</label>
        <select
          id="customerId"
          className="form-select"
          value={form.customerId}
          onChange={(e) => updateField("customerId", e.target.value)}
          disabled={loadingCustomers || submitting}
          required
        >
          <option value="">
            {loadingCustomers ? "Loading customers..." : "Select customer"}
          </option>
          {customers.map((customer) => {
            const firstName = customer.profile?.firstName ?? "";
            const lastName = customer.profile?.lastName ?? "";
            const email = customer.profile?.email ?? customer.username;
            const displayName =
              `${firstName} ${lastName}`.trim() || customer.username;

            return (
              <option key={customer._id} value={customer._id}>
                {displayName} ({email})
              </option>
            );
          })}
        </select>
      </div>

      <div>
        <label htmlFor="coverageAmount">Coverage Amount</label>
        <input
          id="coverageAmount"
          type="number"
          min="0"
          step="0.01"
          value={form.coverageAmount}
          onChange={(e) => updateField("coverageAmount", e.target.value)}
          required
        />
      </div>

      <div>
        <label htmlFor="premiumAmount">Premium Amount</label>
        <input
          id="premiumAmount"
          type="number"
          min="0"
          step="0.01"
          value={form.premiumAmount}
          onChange={(e) => updateField("premiumAmount", e.target.value)}
          required
        />
      </div>

      <div>
        <label htmlFor="effectiveDate">Effective Date</label>
        <input
          id="effectiveDate"
          type="date"
          value={form.effectiveDate}
          onChange={(e) => updateField("effectiveDate", e.target.value)}
          required
        />
      </div>

      <div>
        <label htmlFor="expiryDate">Expiry Date</label>
        <input
          id="expiryDate"
          type="date"
          value={form.expiryDate}
          onChange={(e) => updateField("expiryDate", e.target.value)}
          required
        />
      </div>

      {error ? (
        <div className="full-span">
          <Alert variant="error" message={error} />
        </div>
      ) : null}

      <div className="full-span">
        <button
          className="btn btn-primary"
          type="submit"
          disabled={submitting || loadingCustomers}
        >
          {submitting ? "Saving..." : submitLabel}
        </button>
      </div>
    </form>
  );
}