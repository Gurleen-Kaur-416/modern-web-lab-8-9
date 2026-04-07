export function successResponse(res, data = null, message = "Success", status = 200) {
  return res.status(status).json({
    success: true,
    message,
    data
  });
}

export function errorResponse(res, message = "Request failed", status = 400, errors = null) {
  return res.status(status).json({
    success: false,
    message,
    errors
  });
}

export function paginatedResponse(
  res,
  items,
  {
    page = 1,
    pageSize = 10,
    totalItems = 0,
    message = "Success",
    status = 200
  } = {}
) {
  const totalPages = pageSize > 0 ? Math.ceil(totalItems / pageSize) : 0;

  return res.status(status).json({
    success: true,
    message,
    data: items,
    pagination: {
      page,
      pageSize,
      totalItems,
      totalPages
    }
  });
}