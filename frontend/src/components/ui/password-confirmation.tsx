import { useState, useEffect } from 'react'
import { Check, X, Eye, EyeOff } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'

interface PasswordConfirmationProps {
  password: string
  confirmPassword: string
  onConfirmPasswordChange: (value: string) => void
  onValidationChange?: (isValid: boolean) => void
  error?: string
  className?: string
}

export function PasswordConfirmation({
  password,
  confirmPassword,
  onConfirmPasswordChange,
  onValidationChange,
  error,
  className
}: PasswordConfirmationProps) {
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [showFeedback, setShowFeedback] = useState(false)
  const [hasInteracted, setHasInteracted] = useState(false)

  // Calculate validation state
  const passwordsMatch = password === confirmPassword && confirmPassword.length > 0
  const hasError = hasInteracted && confirmPassword.length > 0 && !passwordsMatch
  const showSuccess = hasInteracted && passwordsMatch

  useEffect(() => {
    // Notify parent component about validation status
    onValidationChange?.(passwordsMatch)
  }, [passwordsMatch, onValidationChange])

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value
    onConfirmPasswordChange(value)
    
    if (!hasInteracted && value.length > 0) {
      setHasInteracted(true)
    }
  }

  const handleFocus = () => {
    setShowFeedback(true)
  }

  const handleBlur = () => {
    setShowFeedback(false)
  }

  const getStatusMessage = () => {
    if (!hasInteracted || confirmPassword.length === 0) {
      return 'Ketik ulang password yang sama'
    }
    
    if (passwordsMatch) {
      return 'Password cocok!'
    }
    
    if (confirmPassword.length < password.length) {
      const remaining = password.length - confirmPassword.length
      return `${remaining} karakter lagi`
    }
    
    return 'Password tidak cocok'
  }

  const getStatusColor = () => {
    if (!hasInteracted || confirmPassword.length === 0) {
      return 'text-muted-foreground'
    }

    return passwordsMatch ? 'text-foreground font-medium' : 'text-muted-foreground'
  }

  return (
    <div className={cn('space-y-2', className)}>
      <Label htmlFor="confirmPassword">Konfirmasi Password</Label>
      
      <div className="relative">
        <Input
          id="confirmPassword"
          type={showConfirmPassword ? 'text' : 'password'}
          placeholder="Ketik ulang password"
          value={confirmPassword}
          onChange={handleInputChange}
          onFocus={handleFocus}
          onBlur={handleBlur}
          className={cn(
            'pr-20',
            showSuccess ? 'border-foreground focus:border-foreground' :
            hasError ? 'border-muted-foreground focus:border-muted-foreground' :
            error ? 'border-destructive' : ''
          )}
        />
        
        {/* Validation Icon */}
        {hasInteracted && confirmPassword.length > 0 && (
          <div className="absolute right-12 top-1/2 -translate-y-1/2">
            {passwordsMatch ? (
              <Check className="h-4 w-4 text-foreground" />
            ) : (
              <X className="h-4 w-4 text-muted-foreground" />
            )}
          </div>
        )}
        
        {/* Show/Hide Password Toggle */}
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
          onClick={() => setShowConfirmPassword(!showConfirmPassword)}
        >
          {showConfirmPassword ? (
            <EyeOff className="h-4 w-4" />
          ) : (
            <Eye className="h-4 w-4" />
          )}
        </Button>
      </div>

      {/* Error Message from Form Validation */}
      {error && (
        <p className="text-sm text-destructive">{error}</p>
      )}

      {/* Interactive Feedback */}
      {showFeedback && hasInteracted && confirmPassword.length > 0 && (
        <div className="space-y-2 animate-in slide-in-from-top-2 fade-in duration-200">
          {/* Progress Indicator */}
          <div className="flex items-center space-x-2">
            <div className={cn(
              'h-1 flex-1 rounded-full transition-colors duration-300',
              passwordsMatch ? 'bg-foreground' : 'bg-muted-foreground'
            )} />
          </div>
          
          {/* Status Message */}
          <p className={cn(
            'text-sm transition-colors duration-200',
            getStatusColor()
          )}>
            {getStatusMessage()}
          </p>
        </div>
      )}
    </div>
  )
}
