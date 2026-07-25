import {
  Activity,
  Bell,
  LayoutDashboard,
  Search,
  Settings,
} from 'lucide-react'

import type { NavItem } from '@/types'

export const NAV_ITEMS: NavItem[] = [
  { title: 'Dashboard', href: '/', icon: LayoutDashboard },
  { title: 'Alerts', href: '/alerts', icon: Bell },
  { title: 'Investigation', href: '/investigation', icon: Search },
  { title: 'Analytics', href: '/analytics', icon: Activity },
  { title: 'Settings', href: '/settings', icon: Settings },
]
