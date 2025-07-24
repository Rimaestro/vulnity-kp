import { z } from 'zod'

export const loginSchema = z.object({
  username: z
    .string()
    .min(1, 'Email atau username harus diisi')
    .refine((value) => {
      // Allow email format OR username format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
      const usernameRegex = /^[a-zA-Z0-9_-]+$/
      return emailRegex.test(value) || (usernameRegex.test(value) && value.length >= 3)
    }, 'Masukkan email yang valid atau username minimal 3 karakter'),
  password: z
    .string()
    .min(1, 'Password harus diisi')
    .min(6, 'Password minimal 6 karakter'),
})

export const registerSchema = z.object({
  username: z
    .string()
    .min(1, 'Username harus diisi')
    .min(3, 'Username minimal 3 karakter')
    .max(50, 'Username maksimal 50 karakter')
    .regex(/^[a-zA-Z0-9_]+$/, 'Username hanya boleh mengandung huruf, angka, dan underscore'),
  email: z
    .string()
    .min(1, 'Email harus diisi')
    .email('Format email tidak valid'),
  password: z
    .string()
    .min(1, 'Password harus diisi')
    .min(6, 'Password minimal 6 karakter')
    .max(100, 'Password maksimal 100 karakter'),
  confirmPassword: z
    .string()
    .min(1, 'Konfirmasi password harus diisi'),
  full_name: z
    .string()
    .max(100, 'Nama lengkap maksimal 100 karakter')
    .optional(),
  terms: z
    .boolean()
    .refine(val => val === true, 'Anda harus menyetujui syarat dan ketentuan'),
}).refine((data) => data.password === data.confirmPassword, {
  message: 'Password dan konfirmasi password tidak cocok',
  path: ['confirmPassword'],
})

export type LoginFormData = z.infer<typeof loginSchema>

// Helper function to determine if input is email or username
export const isEmailFormat = (input: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(input)
}
export type RegisterFormData = z.infer<typeof registerSchema>
