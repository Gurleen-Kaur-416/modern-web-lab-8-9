/**
 * tokenBlocklistService.js
 *
 * In-memory JWT blocklist used to invalidate tokens on logout.
 *
 * Tokens are stored with their expiry timestamp in milliseconds so
 * the set never grows unbounded – expired entries are pruned each
 * time a new token is added.
 *
 * For a production deployment replace the Map with a Redis SET
 * (SETEX key ttl "1") so the store survives server restarts and
 * scales across multiple instances.  The public interface is
 * identical so the swap requires no changes outside this file.
 */

/** @type {Map<string, number>}  raw JWT string → expiry epoch (ms) */
const _store = new Map()

/**
 * Mark a token as revoked.
 *
 * @param {string} token  - The raw JWT string to blocklist.
 * @param {number} expMs  - Unix epoch in **milliseconds** when the token
 *                          expires naturally.  Entries are auto-removed
 *                          after this point to keep memory bounded.
 */
function add(token, expMs) {
  _prune()
  _store.set(token, expMs)
}

/**
 * Returns `true` when the token has been explicitly revoked AND its
 * natural expiry has not yet passed.  A token whose natural expiry
 * has already passed is treated as not revoked (it is invalid for
 * other reasons and `jwt.verify` will reject it independently).
 *
 * @param  {string}  token
 * @returns {boolean}
 */
function has(token) {
  if (!_store.has(token)) return false

  const expMs = _store.get(token)

  // If the token has expired naturally it can no longer be used anyway;
  // remove the entry to keep memory tidy.
  if (Date.now() > expMs) {
    _store.delete(token)
    return false
  }

  return true
}

/**
 * Remove all entries whose natural expiry has already passed.
 * Called automatically on every `add` call.
 */
function _prune() {
  const now = Date.now()
  for (const [token, expMs] of _store.entries()) {
    if (now > expMs) {
      _store.delete(token)
    }
  }
}

export const tokenBlocklistService = { add, has }
