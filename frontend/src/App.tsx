import { ChakraProvider, theme } from '@chakra-ui/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import HomePage from './pages/HomePage'
import ScanDetailPage from './pages/ScanDetailPage'

const queryClient = new QueryClient()

function App() {
  return (
    <ChakraProvider theme={theme}>
      <QueryClientProvider client={queryClient}>
        <Router>
          <Layout>
            <Routes>
              <Route path="/" element={<HomePage />} />
              <Route path="/scan/:scanId" element={<ScanDetailPage />} />
            </Routes>
          </Layout>
        </Router>
      </QueryClientProvider>
    </ChakraProvider>
  )
}

export default App
