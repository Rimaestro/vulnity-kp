import React from 'react'
import {
  Box,
  Heading,
  Text,
  VStack,
  HStack,
  Badge,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Card,
  CardHeader,
  CardBody,
  Stat,
  StatLabel,
  StatNumber,
  StatGroup,
  Divider,
} from '@chakra-ui/react'
import type { ScanResult } from '../types/scan'

interface ScanDetailProps {
  scan: ScanResult
}

const ScanDetail: React.FC<ScanDetailProps> = ({ scan }) => {
  // Format tanggal
  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString('id-ID', {
      dateStyle: 'medium',
      timeStyle: 'medium'
    })
  }

  // Mendapatkan warna badge berdasarkan status
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

  // Mendapatkan warna badge berdasarkan severity
  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'red'
      case 'high':
        return 'orange'
      case 'medium':
        return 'yellow'
      case 'low':
        return 'blue'
      case 'info':
        return 'gray'
      default:
        return 'gray'
    }
  }

  return (
    <VStack spacing={6} align="stretch" w="full">
      {/* Header */}
      <Box>
        <HStack justify="space-between" align="center">
          <Heading size="lg">Detail Pemindaian</Heading>
          <Badge
            colorScheme={getStatusColor(scan.status)}
            fontSize="md"
            px={3}
            py={1}
            borderRadius="full"
          >
            {scan.status}
          </Badge>
        </HStack>
        <Text color="gray.500" mt={2}>
          ID: {scan.id}
        </Text>
      </Box>

      <Divider />

      {/* Statistik */}
      <Card>
        <CardHeader>
          <Heading size="md">Informasi Umum</Heading>
        </CardHeader>
        <CardBody>
          <StatGroup>
            <Stat>
              <StatLabel>Target URL</StatLabel>
              <StatNumber fontSize="md">{scan.url}</StatNumber>
            </Stat>
            <Stat>
              <StatLabel>Waktu Mulai</StatLabel>
              <StatNumber fontSize="md">{formatDate(scan.created_at)}</StatNumber>
            </Stat>
            <Stat>
              <StatLabel>Waktu Selesai</StatLabel>
              <StatNumber fontSize="md">
                {scan.completed_at ? formatDate(scan.completed_at) : '-'}
              </StatNumber>
            </Stat>
          </StatGroup>
        </CardBody>
      </Card>

      {/* Tabel Kerentanan */}
      <Card>
        <CardHeader>
          <Heading size="md">Kerentanan yang Ditemukan</Heading>
        </CardHeader>
        <CardBody>
          <Table variant="simple">
            <Thead>
              <Tr>
                <Th>Tipe</Th>
                <Th>Severity</Th>
                <Th>Lokasi</Th>
                <Th>Deskripsi</Th>
              </Tr>
            </Thead>
            <Tbody>
              {scan.vulnerabilities.map((vuln, index) => (
                <Tr key={index}>
                  <Td>{vuln.type}</Td>
                  <Td>
                    <Badge colorScheme={getSeverityColor(vuln.severity)}>
                      {vuln.severity}
                    </Badge>
                  </Td>
                  <Td>{vuln.location}</Td>
                  <Td>{vuln.description}</Td>
                </Tr>
              ))}
              {scan.vulnerabilities.length === 0 && (
                <Tr>
                  <Td colSpan={4} textAlign="center">
                    Tidak ada kerentanan yang ditemukan
                  </Td>
                </Tr>
              )}
            </Tbody>
          </Table>
        </CardBody>
      </Card>

      {/* Bukti */}
      <Card>
        <CardHeader>
          <Heading size="md">Detail Bukti</Heading>
        </CardHeader>
        <CardBody>
          <VStack align="stretch" spacing={4}>
            {scan.vulnerabilities.map((vuln, index) => (
              <Box key={index} p={4} bg="gray.50" borderRadius="md">
                <Text fontWeight="bold" mb={2}>
                  {vuln.type} - {vuln.location}
                </Text>
                <Text whiteSpace="pre-wrap" fontFamily="monospace">
                  {vuln.evidence}
                </Text>
              </Box>
            ))}
          </VStack>
        </CardBody>
      </Card>
    </VStack>
  )
}

export default ScanDetail 