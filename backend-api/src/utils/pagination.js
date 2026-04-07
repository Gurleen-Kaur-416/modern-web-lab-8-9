export function getPagination(query = {}, defaultPageSize = 10, maxPageSize = 100) {
  const page = Math.max(Number(query.page) || 1, 1);
  const requestedPageSize = Math.max(Number(query.pageSize) || defaultPageSize, 1);
  const pageSize = Math.min(requestedPageSize, maxPageSize);
  const skip = (page - 1) * pageSize;

  return {
    page,
    pageSize,
    skip
  };
}