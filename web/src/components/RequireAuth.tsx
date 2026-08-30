// 路由守卫：未登录（无 admin token）时重定向到 /login，并记录来源页。

import { Navigate, Outlet, useLocation } from "react-router-dom";

import { useAdminToken } from "../hooks/useAdminToken";

export default function RequireAuth() {
  const token = useAdminToken();
  const location = useLocation();

  if (!token) {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  }
  return <Outlet />;
}
