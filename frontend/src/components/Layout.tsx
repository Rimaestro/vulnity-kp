import React from 'react'
import { Box } from '@chakra-ui/react'
import Navbar from './Navbar'

interface LayoutProps {
  children: React.ReactNode
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  return (
    <Box minH="100vh" bg="gray.50">
      <Navbar />
      <Box as="main" py={4}>
        {children}
      </Box>
    </Box>
  )
}

export default Layout 