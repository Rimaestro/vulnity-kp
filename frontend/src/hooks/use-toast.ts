import { toast as sonnerToast } from 'sonner'

export interface ToastProps {
  title?: string
  description?: string
  variant?: 'default' | 'destructive' | 'success' | 'warning' | 'info'
  duration?: number
  action?: {
    label: string
    onClick: () => void
  }
}

export function useToast() {
  const toast = ({ title, description, variant = 'default', duration, action }: ToastProps) => {
    const message = title || description || ''
    const options: any = {
      duration: duration || 4000,
    }

    // Add action if provided
    if (action) {
      options.action = {
        label: action.label,
        onClick: action.onClick,
      }
    }

    // Handle different variants
    switch (variant) {
      case 'destructive':
        return sonnerToast.error(title, {
          description,
          ...options,
        })
      case 'success':
        return sonnerToast.success(title, {
          description,
          ...options,
        })
      case 'warning':
        return sonnerToast.warning(title, {
          description,
          ...options,
        })
      case 'info':
        return sonnerToast.info(title, {
          description,
          ...options,
        })
      default:
        return sonnerToast(title, {
          description,
          ...options,
        })
    }
  }

  return {
    toast,
    dismiss: sonnerToast.dismiss,
    loading: sonnerToast.loading,
    success: sonnerToast.success,
    error: sonnerToast.error,
    warning: sonnerToast.warning,
    info: sonnerToast.info,
  }
}
