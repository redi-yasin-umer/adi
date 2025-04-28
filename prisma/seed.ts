
 /* eslint-disable @typescript-eslint/no-unused-vars */
 import { PrismaClient } from '@prisma/client'
 import { hash } from 'bcryptjs'
 
 const prisma = new PrismaClient()
 
 async function main() {
   // Create admin user
   const adminPassword = await hash('admin123', 12)
   const admin = await prisma.user.upsert({
     where: { email: 'admin@example.com' },
     update: {},
     create: {
       email: 'admin@example.com',
       name: 'Admin User',
       password: adminPassword,
       role: 'ADMIN',
     },
   })
 
   // Create regular user
   const userPassword = await hash('user123', 12)
   const user = await prisma.user.upsert({
     where: { email: 'user@example.com' },
     update: {},
     create: {
       email: 'user@example.com',
       name: 'Regular User',
       password: userPassword,
       role: 'USER',
     },
   })
 
   // Create categories
   const tshirts = await prisma.category.upsert({
     where: { name: 'T-shirts' },
     update: {},
     create: {
       name: 'T-shirts',
       description: 'Comfortable and stylish t-shirts',
       image: '/images/c-tshirts.jpg',
     },
   })
 
   const jeans = await prisma.category.upsert({
     where: { name: 'Jeans' },
     update: {},
     create: {
       name: 'Jeans',
       description: 'Classic and trendy jeans',
       image: '/images/c-jeans.jpg',
     },
   })
 
   const shoes = await prisma.category.upsert({
     where: { name: 'Shoes' },
     update: {},
     create: {
       name: 'Shoes',
       description: 'Comfortable and stylish shoes',
       image: '/images/c-shoes.jpg',
     },
   })
 
   // Create products
   // T-shirts
   await prisma.product.upsert({
     where: { id: 'tshirt-1' },
     update: {},
     create: {
       id: 'tshirt-1',
       name: 'Classic White T-Shirt',
       description: 'A comfortable white t-shirt made from 100% cotton',
       price: 29.99,
       images: ['/images/p11-1.jpg', '/images/p11-2.jpg'],
       categoryId: tshirts.id,
       stock: 50,
     },
   })
 
   await prisma.product.upsert({
     where: { id: 'tshirt-2' },
     update: {},
     create: {
       id: 'tshirt-2',
       name: 'Graphic Print T-Shirt',
       description: 'A stylish graphic print t-shirt with modern design',
       price: 34.99,
       images: ['/images/p12-1.jpg', '/images/p12-2.jpg'],
       categoryId: tshirts.id,
       stock: 30,
     },
   })
 
   // Jeans
   await prisma.product.upsert({
     where: { id: 'jeans-1' },
     update: {},
     create: {
       id: 'jeans-1',
       name: 'Classic Blue Jeans',
       description: 'Classic fit blue jeans with comfortable stretch',
       price: 59.99,
       images: ['/images/p21-1.jpg', '/images/p21-2.jpg'],
       categoryId: jeans.id,
       stock: 40,
     },
   })
 
   await prisma.product.upsert({
     where: { id: 'jeans-2' },
     update: {},
     create: {
       id: 'jeans-2',
       name: 'Slim Fit Black Jeans',
       description: 'Modern slim fit black jeans with premium denim',
       price: 64.99,
       images: ['/images/p22-1.jpg', '/images/p22-2.jpg'],
       categoryId: jeans.id,
       stock: 35,
     },
   })
 
   // Shoes
   await prisma.product.upsert({
     where: { id: 'shoes-1' },
     update: {},
     create: {
       id: 'shoes-1',
       name: 'Classic Sneakers',
       description: 'Comfortable everyday sneakers with great support',
       price: 79.99,
       images: ['/images/p31-1.jpg', '/images/p31-2.jpg'],
       categoryId: shoes.id,
       stock: 25,
     },
   })
 
   await prisma.product.upsert({
     where: { id: 'shoes-2' },
     update: {},
     create: {
       id: 'shoes-2',
       name: 'Running Shoes',
       description: 'High-performance running shoes with advanced cushioning',
       price: 89.99,
       images: ['/images/p32-1.jpg', '/images/p32-2.jpg'],
       categoryId: shoes.id,
       stock: 20,
     },
   })
 
   console.log('Seed data created successfully')
 }
 
 main()
   .catch((e) => {
     console.error(e)
     process.exit(1)
   })
   .finally(async () => {
     await prisma.$disconnect()
   })