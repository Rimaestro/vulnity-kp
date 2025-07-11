import React from 'react'
import { Link as RouterLink } from 'react-router-dom'
import {
  Box,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  Link,
  Heading,
  Card,
  CardHeader,
  CardBody,
  Spinner,
  Text,
} from '@chakra-ui/react'
import { useQuery } from '@tanstack/react-query'
import { scanApi } from '../services/api'
import type { ScanResult } from '../types/scan'

const ScanResults: React.FC = () => {
  const { data: scans = [], isLoading, error } = useQuery({
    queryKey: ['scans'],
    queryFn: scanApi.getAllScans,
    refetchInterval: 5000, // Refresh setiap 5 detik
  })

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed':
        return 'green'
      case 'running':
        return 'blue'
      case 'failed':
        return 'red'
      case 'pending':
        return 'yellow'
      default:
        return 'gray'
    }
  }

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center">
        <Spinner size="xl" />
      </Box>
    )
  }

  if (error) {
    return <Box>Error memuat data</Box>
  }

  return (
    <Card w="full">
      <CardHeader>
        <Heading size="md">Riwayat Pemindaian</Heading>
      </CardHeader>
      <CardBody>
        {scans.length === 0 ? (
          <Text textAlign="center">Belum ada pemindaian yang dilakukan</Text>
        ) : (
          <Table variant="simple">
            <Thead>
              <Tr>
                <Th>Target</Th>
                <Th>Status</Th>
                <Th>Waktu Mulai</Th>
                <Th>Kerentanan</Th>
                <Th>Aksi</Th>
              </Tr>
            </Thead>
            <Tbody>
              {scans.map((scan) => (
                <Tr key={scan.id}>
                  <Td>{scan.url}</Td>
                  <Td>
                    <Badge colorScheme={getStatusColor(scan.status)}>
                      {scan.status}
                    </Badge>
                  </Td>
                  <Td>
                    {new Date(scan.created_at).toLocaleString('id-ID', {
                      dateStyle: 'medium',
                      timeStyle: 'short',
                    })}
                  </Td>
                  <Td>{scan.vulnerabilities.length}</Td>
                  <Td>
                    <Link
                      as={RouterLink}
                      to={`/scan/${scan.id}`}
                      color="blue.500"
                    >
                      Lihat Detail
                    </Link>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </CardBody>
    </Card>
  )
}

export default ScanResults 