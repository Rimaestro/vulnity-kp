import { useState } from 'react'
import {
  Box,
  Button,
  FormControl,
  FormLabel,
  Input,
  NumberInput,
  NumberInputField,
  Switch,
  VStack,
  useToast,
} from '@chakra-ui/react'
import { Play } from 'lucide-react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { scanApi } from '../services/api'
import type { ScanOptions } from '../types/scan'

const ScanForm = () => {
  const toast = useToast()
  const [url, setUrl] = useState('')
  const [maxDepth, setMaxDepth] = useState(3)
  const [threads, setThreads] = useState(10)
  const [timeout, setTimeout] = useState(30)
  const [followRedirects, setFollowRedirects] = useState(true)

  const { data: plugins = [] } = useQuery({
    queryKey: ['plugins'],
    queryFn: scanApi.getPlugins,
  })

  const scanMutation = useMutation({
    mutationFn: scanApi.startScan,
    onSuccess: () => {
      toast({
        title: 'Pemindaian dimulai',
        status: 'success',
        duration: 3000,
      })
      setUrl('')
    },
    onError: (error: any) => {
      toast({
        title: 'Gagal memulai pemindaian',
        description: error.response?.data?.detail || 'Terjadi kesalahan',
        status: 'error',
        duration: 3000,
      })
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    // Log data yang akan dikirim
    console.log('Plugins:', plugins)
    
    const scanRequest = {
      url,
      scan_types: plugins,
      options: {
        max_depth: maxDepth,
        threads,
        timeout,
        follow_redirects: followRedirects,
      },
    }

    console.log('Sending scan request:', scanRequest)
    scanMutation.mutate(scanRequest)
  }

  return (
    <Box as="form" onSubmit={handleSubmit}>
      <VStack spacing={4} align="stretch">
        <FormControl isRequired>
          <FormLabel>URL Target</FormLabel>
          <Input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
          />
        </FormControl>

        <FormControl>
          <FormLabel>Max Depth</FormLabel>
          <NumberInput value={maxDepth} onChange={(_, val) => setMaxDepth(val)} min={1}>
            <NumberInputField />
          </NumberInput>
        </FormControl>

        <FormControl>
          <FormLabel>Threads</FormLabel>
          <NumberInput value={threads} onChange={(_, val) => setThreads(val)} min={1}>
            <NumberInputField />
          </NumberInput>
        </FormControl>

        <FormControl>
          <FormLabel>Timeout (seconds)</FormLabel>
          <NumberInput value={timeout} onChange={(_, val) => setTimeout(val)} min={1}>
            <NumberInputField />
          </NumberInput>
        </FormControl>

        <FormControl display="flex" alignItems="center">
          <FormLabel mb="0">Follow Redirects</FormLabel>
          <Switch
            isChecked={followRedirects}
            onChange={(e) => setFollowRedirects(e.target.checked)}
          />
        </FormControl>

        <Button
          type="submit"
          leftIcon={<Play size={20} />}
          isLoading={scanMutation.isPending}
          colorScheme="blackAlpha"
        >
          Mulai Pemindaian
        </Button>
      </VStack>
    </Box>
  )
}

export default ScanForm 