import React from 'react'
import { Container, VStack } from '@chakra-ui/react'
import ScanForm from '../components/ScanForm'
import ScanResults from '../components/ScanResults'

const HomePage: React.FC = () => {
  return (
    <Container maxW="container.xl" py={8}>
      <VStack spacing={8}>
        <ScanForm />
        <ScanResults />
      </VStack>
    </Container>
  )
}

export default HomePage 