import { Box, Container, Flex, Heading, IconButton } from '@chakra-ui/react'
import { Menu, Search, Shield } from 'lucide-react'
import { Link } from 'react-router-dom'

const Navbar = () => {
  return (
    <Box bg="black" color="white" py={4}>
      <Container maxW="container.xl">
        <Flex justify="space-between" align="center">
          <Flex align="center" gap={8}>
            <Link to="/">
              <Flex align="center" gap={2}>
                <Shield size={24} />
                <Heading size="md">Vulnity</Heading>
              </Flex>
            </Link>
          </Flex>
          
          <Flex gap={4}>
            <IconButton
              aria-label="Search"
              as={Search}
              variant="ghost"
              color="white"
              _hover={{ bg: 'whiteAlpha.200' }}
            />
            <IconButton
              aria-label="Menu"
              as={Menu}
              variant="ghost"
              color="white"
              _hover={{ bg: 'whiteAlpha.200' }}
            />
          </Flex>
        </Flex>
      </Container>
    </Box>
  )
}

export default Navbar 