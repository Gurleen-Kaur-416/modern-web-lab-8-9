import { AppError } from "../utils/appError.js";
import { userRepository } from "../repositories/userRepository.js";
import { roleRepository } from "../repositories/roleRepository.js";

function buildDisplayName(identity) {
  if (identity.fullName) {
    return identity.fullName;
  }

  const combined = `${identity.givenName || ""} ${identity.familyName || ""}`.trim();
  return combined || identity.username || identity.email || "Keycloak User";
}

export async function findOrProvisionUserFromKeycloak(identity) {
  let user = null;

  if (identity.email) {
    user = await userRepository.findByEmail(identity.email);
  }

  if (!user && identity.username) {
    user = await userRepository.findByUsername(identity.username);
  }

  if (user) {
    return user;
  }

  if (!identity.roles || identity.roles.length === 0) {
    throw new AppError("Keycloak user has no mapped application roles", 403);
  }

  const roleDocs = await roleRepository.findByNames(identity.roles);

  if (!roleDocs || roleDocs.length === 0) {
    throw new AppError("No matching local roles found for Keycloak user", 403);
  }

  return userRepository.create({
    username: identity.username || identity.email,
    email: identity.email || "",
    fullName: buildDisplayName(identity),
    authProvider: "KEYCLOAK",
    externalSubject: identity.sub,
    enabled: true,
    roles: roleDocs.map((role) => role._id)
  });
}