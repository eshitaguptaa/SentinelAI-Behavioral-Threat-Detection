import { useState } from 'react'
import { Outlet } from 'react-router-dom'
import { Menu, Shield } from 'lucide-react'

import { SidebarNav } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '@/components/ui/sheet'
import { ScrollArea } from '@/components/ui/scroll-area'

function BrandMark() {
  return (
    <div className="flex items-center gap-2 px-3 py-1">
      <Shield className="size-5 text-primary" aria-hidden />
      <span className="text-base font-semibold tracking-tight">SentinelAI</span>
    </div>
  )
}

function DesktopSidebar() {
  return (
    <aside className="bg-sidebar text-sidebar-foreground border-sidebar-border hidden w-64 shrink-0 border-r md:flex md:flex-col">
      <div className="flex h-14 items-center px-3">
        <BrandMark />
      </div>
      <Separator />
      <ScrollArea className="flex-1 px-3 py-4">
        <SidebarNav />
      </ScrollArea>
    </aside>
  )
}

function MobileSidebar() {
  const [open, setOpen] = useState(false)

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button variant="outline" size="icon" className="md:hidden" aria-label="Open navigation">
          <Menu className="size-4" />
        </Button>
      </SheetTrigger>
      <SheetContent side="left" className="bg-sidebar text-sidebar-foreground w-72 p-0">
        <SheetHeader className="border-sidebar-border border-b">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <BrandMark />
        </SheetHeader>
        <ScrollArea className="h-[calc(100svh-4rem)] px-3 py-4">
          <SidebarNav onNavigate={() => setOpen(false)} />
        </ScrollArea>
      </SheetContent>
    </Sheet>
  )
}

export function MainLayout() {
  return (
    <div className="bg-background text-foreground flex min-h-svh w-full">
      <DesktopSidebar />

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="bg-background/80 border-border sticky top-0 z-10 flex h-14 items-center gap-3 border-b px-4 backdrop-blur md:px-6">
          <MobileSidebar />
          <p className="text-muted-foreground text-sm md:hidden">SentinelAI</p>
        </header>

        <main className="flex-1 p-4 md:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
