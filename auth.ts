import NextAuth, { DefaultSession } from 'next-auth'
import prisma from '@/lib/prisma'
import bcrypt from 'bcryptjs'
import GitHub from 'next-auth/providers/github'
import Google from 'next-auth/providers/google'
import Credentials from 'next-auth/providers/credentials'
// Remove or comment out this line:
// import { User } from '@prisma/client'

declare module 'next-auth' {
  interface Session {
    user: {
      role?: 'USER' | 'ADMIN'
    } & DefaultSession['user']
  }
}

export const { handlers, signIn, signOut, auth } = NextAuth({
  session: {
    strategy: 'jwt',
  },
  pages: {
    signIn: '/auth/signin',
    error: '/auth/error',
  },
  providers: [
    GitHub({
      clientId: process.env.GITHUB_ID!,
      clientSecret: process.env.GITHUB_SECRET!,
    }),
    Google({
      clientId: process.env.GOOGLE_ID!,
      clientSecret: process.env.GOOGLE_SECRET!,
    }),
    Credentials({
      name: 'credentials',
      credentials: {
        email: { label: 'Email', type: 'email' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          return null
        }

        const email = credentials.email as string
        const password = credentials.password as string

        const user = await prisma.user.findUnique({
          where: { email },
        })

        if (!user || !user.password) {
          return null
        }

        const isPasswordValid = await bcrypt.compare(password, user.password)

        if (!isPasswordValid) {
          return null
        }

        // Return the user object including the role
        return {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role, // Ensure role is included here if using Credentials
        }
      },
    }),
  ],
  callbacks: {
    async signIn({ user, account }) {
      if (account?.provider === 'github' || account?.provider === 'google') {
        if (!user.email) return false

        // Check if user exists
        const existingUser = await prisma.user.findUnique({
          where: { email: user.email },
        })

        if (!existingUser) {
          // Create new user if doesn't exist
          // Note: Role is not set here by default for OAuth providers
          await prisma.user.create({
            data: {
              email: user.email,
              name: user.name,
              image: user.image,
              // You might want to assign a default role here if needed
              // role: 'USER',
            },
          })
        } else {
          // Optionally update existing user data (e.g., image)
          if (user.image && existingUser.image !== user.image) {
            await prisma.user.update({
              where: { email: user.email },
              data: { image: user.image },
            });
          }
        }
      }
      // For Credentials provider, the user object from authorize already includes the role
      return true
    },
    async jwt({ token, user }) {
      // The 'user' object is available on initial sign-in
      if (user) {
        // Check if the 'role' property exists on the user object and assign it to the token
        if ('role' in user && user.role) {
           token.role = user.role as 'USER' | 'ADMIN';
        }
        // Persist the user ID in the token
        token.id = user.id;
      }
      // If the user object isn't available (e.g., subsequent requests),
      // you might need to fetch the role from the database using token.id or token.sub
      // However, the role should already be in the token from the initial sign-in.
      return token
    },
    async session({ session, token }) {
      // Assign the role from the token to the session user object
      if (session.user && token.role) {
        session.user.role = token.role as 'USER' | 'ADMIN'
      }
      // Assign the user ID from the token to the session user object
      if (session.user && token.id) {
        session.user.id = token.id as string;
      }
      return session
    },
  },
})