import { Routes, Route, Navigate } from 'react-router-dom'
import { LandingPage } from '@/pages/landing'
import { LoginPage } from '@/pages/login'
import { RegisterPage } from '@/pages/register'
import { DashboardPage } from '@/pages/dashboard'
import { ScansPage } from '@/pages/scans'
import { NewScanPage } from '@/pages/scans/new'
import { ScanDetailPage } from '@/pages/scans/detail'
import { VulnerabilitiesPage } from '@/pages/vulnerabilities'
import { ProtectedRoute, PublicRoute } from '@/components/auth/protected-route'

function App() {
  return (
    <Routes>
      {/* Public Routes */}
      <Route
        path="/"
        element={
          <PublicRoute>
            <LandingPage />
          </PublicRoute>
        }
      />
      <Route
        path="/login"
        element={
          <PublicRoute>
            <LoginPage />
          </PublicRoute>
        }
      />
      <Route
        path="/register"
        element={
          <PublicRoute>
            <RegisterPage />
          </PublicRoute>
        }
      />

      {/* Protected Routes */}
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <DashboardPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/dashboard/scans"
        element={
          <ProtectedRoute>
            <ScansPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/dashboard/scans/new"
        element={
          <ProtectedRoute>
            <NewScanPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/dashboard/scans/:id"
        element={
          <ProtectedRoute>
            <ScanDetailPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/dashboard/vulnerabilities"
        element={
          <ProtectedRoute>
            <VulnerabilitiesPage />
          </ProtectedRoute>
        }
      />

      {/* Catch all route - redirect to home */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default App
