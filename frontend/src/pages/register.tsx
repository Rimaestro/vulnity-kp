import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Eye, EyeOff, Loader2, ChevronLeft } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Checkbox } from '@/components/ui/checkbox'
import { PasswordRequirements } from '@/components/ui/password-requirements'
import { PasswordConfirmation } from '@/components/ui/password-confirmation'

import { useAuth } from '@/contexts/auth-context'
import { registerSchema, type RegisterFormData } from '@/lib/validations/auth'

export function RegisterPage() {
  const [showPassword, setShowPassword] = useState(false)
  const [passwordValue, setPasswordValue] = useState('')
  const [confirmPasswordValue, setConfirmPasswordValue] = useState('')
  const [showPasswordRequirements, setShowPasswordRequirements] = useState(false)
  const [isPasswordConfirmValid, setIsPasswordConfirmValid] = useState(false)
  const { register: registerUser, error, clearError, isLoading } = useAuth()
  const navigate = useNavigate()

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    setValue,
    watch,
  } = useForm<RegisterFormData>({
    resolver: zodResolver(registerSchema),
  })

  const termsAccepted = watch('terms')

  const onSubmit = async (data: RegisterFormData) => {
    try {
      clearError()

      // Use confirmPasswordValue from state instead of form data
      const { confirmPassword, terms, ...registerData } = data
      const apiData = {
        ...registerData,
        password: passwordValue, // Use state value
        confirm_password: confirmPasswordValue // Use state value
      }

      await registerUser(apiData)
      navigate('/dashboard', { replace: true })
    } catch (error) {
      // Error is handled by auth context
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4 py-8">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1 text-center">
          <CardTitle className="text-2xl">Buat Akun Baru</CardTitle>
          <CardDescription>
            Daftar untuk mulai menggunakan Vulnity vulnerability scanner
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                type="text"
                placeholder="Masukkan username"
                {...register('username')}
                className={errors.username ? 'border-destructive' : ''}
              />
              {errors.username && (
                <p className="text-sm text-destructive">{errors.username.message}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="Masukkan email"
                {...register('email')}
                className={errors.email ? 'border-destructive' : ''}
              />
              {errors.email && (
                <p className="text-sm text-destructive">{errors.email.message}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="full_name">Nama Lengkap (Opsional)</Label>
              <Input
                id="full_name"
                type="text"
                placeholder="Masukkan nama lengkap"
                {...register('full_name')}
                className={errors.full_name ? 'border-destructive' : ''}
              />
              {errors.full_name && (
                <p className="text-sm text-destructive">{errors.full_name.message}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Masukkan password"
                  {...register('password', {
                    onChange: (e) => setPasswordValue(e.target.value)
                  })}
                  onFocus={() => setShowPasswordRequirements(true)}
                  onBlur={() => setShowPasswordRequirements(false)}
                  className={errors.password ? 'border-destructive pr-10' : 'pr-10'}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </Button>
              </div>
              {errors.password && (
                <p className="text-sm text-destructive">{errors.password.message}</p>
              )}

              {/* Password Requirements - Interactive */}
              {showPasswordRequirements && (
                <PasswordRequirements
                  password={passwordValue}
                />
              )}
            </div>

            <PasswordConfirmation
              password={passwordValue}
              confirmPassword={confirmPasswordValue}
              onConfirmPasswordChange={(value) => {
                setConfirmPasswordValue(value)
                // Update form state for validation
                setValue('confirmPassword', value)
              }}
              onValidationChange={setIsPasswordConfirmValid}
              error={errors.confirmPassword?.message}
            />

            <div className="flex items-center space-x-2">
              <Checkbox
                id="terms"
                checked={termsAccepted}
                onCheckedChange={(checked) => setValue('terms', !!checked)}
              />
              <Label
                htmlFor="terms"
                className="text-sm font-normal leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
              >
                Saya menyetujui{' '}
                <Link to="/terms" className="text-primary underline-offset-4 hover:underline">
                  syarat dan ketentuan
                </Link>{' '}
                yang berlaku
              </Label>
            </div>
            {errors.terms && (
              <p className="text-sm text-destructive">{errors.terms.message}</p>
            )}

            <Button
              type="submit"
              className="w-full"
              disabled={isSubmitting || isLoading}
            >
              {isSubmitting || isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Mendaftar...
                </>
              ) : (
                'Daftar'
              )}
            </Button>
          </form>

          <div className="mt-6 text-center text-sm">
            <span className="text-muted-foreground">Sudah punya akun? </span>
            <Link
              to="/login"
              className="text-primary underline-offset-4 hover:underline"
            >
              Masuk sekarang
            </Link>
          </div>

          <div className="mt-4 text-center text-sm">
            <Link
              to="/"
              className="inline-flex items-center text-muted-foreground hover:text-foreground transition-colors"
            >
              <ChevronLeft className="mr-1 h-4 w-4" />
              Kembali ke Beranda
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

export default RegisterPage
