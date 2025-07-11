import React from 'react'
import { Routes, Route } from 'react-router-dom'
import { Layout } from './components/layout/Layout'
import { Dashboard } from './pages/Dashboard'
import { ScanPage } from './pages/ScanPage'
import { ResultsPage } from './pages/ResultsPage'
import { AboutPage } from './pages/AboutPage'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan" element={<ScanPage />} />
        <Route path="/results/:scanId?" element={<ResultsPage />} />
        <Route path="/about" element={<AboutPage />} />
      </Routes>
    </Layout>
  )
}

export default App
