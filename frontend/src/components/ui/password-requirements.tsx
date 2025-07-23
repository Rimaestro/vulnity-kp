import { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'

interface PasswordRequirement {
  id: string
  regex: RegExp
  met: boolean
}

interface PasswordRequirementsProps {
  password: string
  className?: string
  onValidationChange?: (isValid: boolean) => void
}

export function PasswordRequirements({
  password,
  className,
  onValidationChange
}: PasswordRequirementsProps) {
  const [requirements, setRequirements] = useState<PasswordRequirement[]>([
    {
      id: 'minLength',
      regex: /.{8,}/,
      met: false
    },
    {
      id: 'uppercase',
      regex: /[A-Z]/,
      met: false
    },
    {
      id: 'lowercase',
      regex: /[a-z]/,
      met: false
    },
    {
      id: 'number',
      regex: /[0-9]/,
      met: false
    },
    {
      id: 'specialChar',
      regex: /[!@#$%^&*]/,
      met: false
    }
  ])

  useEffect(() => {
    const updatedRequirements = requirements.map(req => ({
      ...req,
      met: req.regex.test(password)
    }))

    setRequirements(updatedRequirements)

    const score = updatedRequirements.filter(req => req.met).length
    const isValid = score === updatedRequirements.length
    onValidationChange?.(isValid)
  }, [password, onValidationChange])

  const getProgressDotColor = (index: number) => {
    const metRequirements = requirements.filter(req => req.met).length
    if (index < metRequirements) {
      return 'bg-foreground' // White in light mode, near-white in dark mode
    }
    return 'bg-muted-foreground' // Black/dark gray
  }

  return (
    <div className={cn(
      'mt-3 space-y-3 animate-in slide-in-from-top-2 fade-in duration-200',
      className
    )}>
      {/* Progress Dots */}
      <div className="flex items-center space-x-2">
        {Array.from({ length: 5 }).map((_, index) => (
          <div
            key={index}
            className={cn(
              'h-1 flex-1 rounded-full transition-colors duration-300',
              getProgressDotColor(index)
            )}
          />
        ))}
      </div>

      {/* Instruction Text */}
      <p className="text-sm text-muted-foreground leading-relaxed">
        Gunakan minimal 8 karakter dengan kombinasi huruf besar, huruf kecil, angka, dan simbol khusus (contoh: @, #, $).
      </p>
    </div>
  )
}
