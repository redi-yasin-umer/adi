
'use client'
 
import Link from 'next/link'
import { Search, ShoppingCart, User } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useSession, signIn } from 'next-auth/react'

export function Header() {
  const { data: session } = useSession()

  return (
    <header className='border-b'>
      <div className='container mx-auto px-4 sm:px-6 lg:px-8'>
        <div className='flex h-16 items-center justify-between'>
          {/* Logo */}
          <div className='flex-shrink-0'>
            <Link href='/' className='text-xl font-bold'>
              Adnan
            </Link>
          </div>

          {/* Search */}
          <div className='hidden sm:block flex-1 max-w-2xl mx-8'>
            <div className='relative'>
              <Input
                type='search'
                placeholder='Search products...'
                className='w-full pl-10'
              />
              <Search className='absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400' />
            </div>
          </div>

          {/* Navigation */}
          <nav className='flex items-center gap-4'>
            <Button variant='ghost' size='icon' asChild>
              <Link href='/search'>
                <Search className='h-5 w-5 sm:hidden' />
              </Link>
            </Button>
            <Button variant='ghost' size='icon' asChild>
              <Link href='/cart'>
                <ShoppingCart className='h-5 w-5' />
              </Link>
            </Button>
            {session ? (
              <Button variant='ghost' size='icon' asChild>
                <Link href='/dashboard'>
                  <User className='h-5 w-5' />
                </Link>
              </Button>
            ) : (
              <Button variant='default' onClick={() => signIn()}>
                Sign In
              </Button>
            )}
          </nav>
        </div>
      </div>
    </header>
  )
}