import { apiRequest } from './api'

export interface LoginRequest {
  email: string
  password: string
}

export interface RegisterRequest {
  email: string
  username: string
  password: string
  full_name?: string
}

export interface AuthResponse {
  access_token: string
  token_type: string
}

export interface User {
  id: number
  email: string
  username: string
  full_name?: string
  role: string
  is_active: boolean
  is_verified: boolean
  created_at: string
}

export const authService = {
  // Login user
  login: async (credentials: LoginRequest): Promise<AuthResponse> => {
    const response = await apiRequest<AuthResponse>('POST', '/v1/auth/login/json', credentials)
    
    // Store token and user info
    localStorage.setItem('access_token', response.access_token)
    
    return response
  },

  // Register new user
  register: async (userData: RegisterRequest): Promise<User> => {
    return apiRequest<User>('POST', '/v1/auth/register', userData)
  },

  // Logout user
  logout: () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('user')
    window.location.href = '/login'
  },

  // Get current user
  getCurrentUser: async (): Promise<User> => {
    return apiRequest<User>('GET', '/v1/auth/me')
  },

  // Check if user is authenticated
  isAuthenticated: (): boolean => {
    const token = localStorage.getItem('access_token')
    return !!token
  },

  // Get stored token
  getToken: (): string | null => {
    return localStorage.getItem('access_token')
  },

  // Get stored user
  getStoredUser: (): User | null => {
    const userStr = localStorage.getItem('user')
    return userStr ? JSON.parse(userStr) : null
  },

  // Store user info
  storeUser: (user: User) => {
    localStorage.setItem('user', JSON.stringify(user))
  }
}

// Export individual functions for easier imports
export const {
  login,
  register,
  logout,
  getCurrentUser,
  isAuthenticated,
  getToken,
  getStoredUser,
  storeUser
} = authService
