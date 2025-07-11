export interface User {
  id: number
  email: string
  username: string
  full_name?: string
  role: 'admin' | 'user'
  bio?: string
  is_active: boolean
  is_verified: boolean
  created_at: string
  updated_at?: string
  last_login?: string
  profile_picture?: string
}

export interface LoginRequest {
  email: string
  password: string
}

export interface RegisterRequest {
  email: string
  username: string
  password: string
  full_name?: string
  bio?: string
}

export interface AuthResponse {
  access_token: string
  token_type: string
}

export interface AuthState {
  user: User | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
  error: string | null
}
