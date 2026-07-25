import { NavLink } from 'react-router-dom'

import { cn } from '@/lib/utils'
import { NAV_ITEMS } from '@/lib/navigation'

type SidebarNavProps = {
  onNavigate?: () => void
  className?: string
}

export function SidebarNav({ onNavigate, className }: SidebarNavProps) {
  return (
    <nav className={cn('flex flex-col gap-1', className)} aria-label="Main">
      {NAV_ITEMS.map(({ title, href, icon: Icon }) => (
        <NavLink
          key={href}
          to={href}
          end={href === '/'}
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
              isActive
                ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground',
            )
          }
        >
          <Icon className="size-4 shrink-0" aria-hidden />
          <span>{title}</span>
        </NavLink>
      ))}
    </nav>
  )
}
