export function stripSensitiveUserFields(user) {
  if (!user) return null;

  const plainObject =
    typeof user.toObject === "function"
      ? user.toObject()
      : JSON.parse(JSON.stringify(user));

  delete plainObject.passwordHash;
  delete plainObject.__v;

  if (Array.isArray(plainObject.roles)) {
    plainObject.roles = plainObject.roles.map((role) => {
      if (typeof role === "string") return role;
      if (role && typeof role === "object" && role.name) return role.name;
      return String(role);
    });
  }

  return plainObject;
}

export function stripSensitiveUsers(users = []) {
  return users.map(stripSensitiveUserFields);
}

export function omitFields(source, fields = []) {
  if (!source || typeof source !== "object") return source;

  const target =
    typeof source.toObject === "function"
      ? source.toObject()
      : JSON.parse(JSON.stringify(source));

  for (const field of fields) {
    delete target[field];
  }

  return target;
}