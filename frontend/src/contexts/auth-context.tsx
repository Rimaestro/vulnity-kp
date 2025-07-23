import React, { createContext, useContext, useEffect, useState } from 'react'
import type { User } from '@/types/api'
import { authApi } from '@/lib/api'

interface AuthContextType {
  user: User | null
  isLoading: boolean
  isAuthenticated: boolean
  login: (credentials: { username: string; password: string }) => Promise<void>
  register: (userData: { username: string; email: string; password: string; confirm_password: string; full_name?: string }) => Promise<void>
  logout: () => void
  error: string | null
  clearError: () => void
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const isAuthenticated = !!user

  const clearError = () => setError(null)

  // Check if user is already logged in on app start
  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem('access_token')
      if (token) {
        try {
          const response = await authApi.getCurrentUser()
          setUser(response.data.user || response.data)
        } catch (error) {
          // Token might be expired, clear it
          localStorage.removeItem('access_token')
          localStorage.removeItem('refresh_token')
        }
      }
      setIsLoading(false)
    }

    checkAuth()
  }, [])

  const login = async (credentials: { username: string; password: string }) => {
    try {
      setIsLoading(true)
      setError(null)
      
      const response = await authApi.login(credentials)
      const { user: userData, tokens } = response.data
      
      // Store tokens
      localStorage.setItem('access_token', tokens.access_token)
      localStorage.setItem('refresh_token', tokens.refresh_token)
      
      setUser(userData)
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || 
                          error.response?.data?.detail || 
                          'Login failed. Please check your credentials.'
      setError(errorMessage)
      throw error
    } finally {
      setIsLoading(false)
    }
  }

  const register = async (userData: { username: string; email: string; password: string; confirm_password: string; full_name?: string }) => {
    try {
      setIsLoading(true)
      setError(null)
      
      const response = await authApi.register(userData)
      const { user: newUser, tokens } = response.data
      
      // Store tokens
      localStorage.setItem('access_token', tokens.access_token)
      localStorage.setItem('refresh_token', tokens.refresh_token)
      
      setUser(newUser)
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || 
                          error.response?.data?.detail || 
                          'Registration failed. Please try again.'
      setError(errorMessage)
      throw error
    } finally {
      setIsLoading(false)
    }
  }

  const logout = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    setUser(null)
    setError(null)
    
    // Optional: Call logout endpoint
    authApi.logout().catch(() => {
      // Ignore errors on logout
    })
  }

  const value: AuthContextType = {
    user,
    isLoading,
    isAuthenticated,
    login,
    register,
    logout,
    error,
    clearError,
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
