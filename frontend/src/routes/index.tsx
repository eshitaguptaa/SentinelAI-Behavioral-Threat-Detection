import { Navigate, type RouteObject } from 'react-router-dom'

import { MainLayout } from '@/layouts'
import {
  AlertsPage,
  AnalyticsPage,
  DashboardPage,
  InvestigationPage,
  SettingsPage,
} from '@/pages'

export const appRoutes: RouteObject[] = [
  {
    path: '/',
    element: <MainLayout />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: 'alerts', element: <AlertsPage /> },
      { path: 'investigation', element: <InvestigationPage /> },
      { path: 'analytics', element: <AnalyticsPage /> },
      { path: 'settings', element: <SettingsPage /> },
      { path: '*', element: <Navigate to="/" replace /> },
    ],
  },
]
