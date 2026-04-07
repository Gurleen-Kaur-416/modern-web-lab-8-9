export function formatCurrency(value: number, currency = "CAD"): string {
  return new Intl.NumberFormat("en-CA", {
    style: "currency",
    currency
  }).format(value);
}

export function formatDate(value?: string): string {
  if (!value) return "-";

  return new Intl.DateTimeFormat("en-CA", {
    year: "numeric",
    month: "short",
    day: "2-digit"
  }).format(new Date(value));
}