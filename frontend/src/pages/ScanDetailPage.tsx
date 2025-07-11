import React from 'react'
import { useParams } from 'react-router-dom'
import { Box, Container, Spinner, useToast } from '@chakra-ui/react'
import { useQuery } from '@tanstack/react-query'
import { scanApi } from '../services/api'
import ScanDetail from '../components/ScanDetail'

const ScanDetailPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>()
  const toast = useToast()

  const { data: scan, isLoading, error } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scanApi.getScanResults(scanId!),
    refetchInterval: (data) => {
      // Auto refresh setiap 5 detik jika scan masih berjalan
      if (data?.status === 'running' || data?.status === 'pending') {
        return 5000
      }
      return false
    },
    onError: () => {
      toast({
        title: 'Error',
        description: 'Gagal memuat detail pemindaian',
        status: 'error',
        duration: 3000,
      })
    },
  })

  if (isLoading) {
    return (
      <Container maxW="container.xl" py={8}>
        <Box display="flex" justifyContent="center">
          <Spinner size="xl" />
        </Box>
      </Container>
    )
  }

  if (error || !scan) {
    return (
      <Container maxW="container.xl" py={8}>
        <Box textAlign="center">Error memuat data</Box>
      </Container>
    )
  }

  return (
    <Container maxW="container.xl" py={8}>
      <ScanDetail scan={scan} />
    </Container>
  )
}

export default ScanDetailPage 