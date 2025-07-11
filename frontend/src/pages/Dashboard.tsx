import { Box, Heading, Text, VStack } from '@chakra-ui/react'
import ScanForm from '../components/ScanForm'
import ScanResults from '../components/ScanResults'

const Dashboard = () => {
  return (
    <VStack spacing={8} align="stretch">
      <Box>
        <Heading size="lg" mb={2}>Welcome to Vulnity</Heading>
        <Text color="gray.600">Web Vulnerability Scanner with Plugin-based Architecture</Text>
      </Box>

      <Box bg="white" p={6} borderRadius="lg" borderWidth={1}>
        <VStack align="stretch" spacing={4}>
          <Heading size="md">Start New Scan</Heading>
          <ScanForm />
        </VStack>
      </Box>

      <Box bg="white" p={6} borderRadius="lg" borderWidth={1}>
        <ScanResults />
      </Box>
    </VStack>
  )
}

export default Dashboard 