export function toIsoDate(value) {
  if (!value) return null;
  return new Date(value).toISOString();
}

export function toDateOnly(value) {
  if (!value) return null;

  const date = new Date(value);
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");

  return `${year}-${month}-${day}`;
}

export function isFutureDate(value) {
  if (!value) return false;
  return new Date(value).getTime() > Date.now();
}

export function isPastDate(value) {
  if (!value) return false;
  return new Date(value).getTime() < Date.now();
}

export function nowIso() {
  return new Date().toISOString();
}

export function daysBetween(start, end) {
  const startDate = new Date(start).getTime();
  const endDate = new Date(end).getTime();
  const diff = endDate - startDate;

  return Math.ceil(diff / (1000 * 60 * 60 * 24));
}