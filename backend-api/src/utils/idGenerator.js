function randomSegment(length = 6) {
  return Math.random().toString(36).slice(2, 2 + length).toUpperCase();
}

export function generateBusinessId(prefix = "ID") {
  return `${prefix}-${Date.now()}-${randomSegment(6)}`;
}

export function generatePolicyNumber(type = "GEN") {
  return `${type}-${Date.now()}-${randomSegment(4)}`;
}

export function generateCustomerNumber() {
  return `CUST-${Date.now()}-${randomSegment(4)}`;
}

export function generateEmployeeNumber() {
  return `EMP-${Date.now()}-${randomSegment(4)}`;
}