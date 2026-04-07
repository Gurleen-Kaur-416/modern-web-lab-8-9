export function buildOptionalExactFilters(source = {}, allowedFields = []) {
  const filter = {};

  for (const field of allowedFields) {
    const value = source[field];
    if (value !== undefined && value !== null && value !== "") {
      filter[field] = value;
    }
  }

  return filter;
}