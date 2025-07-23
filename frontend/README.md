# Vulnity Frontend - Interface Pemindai Kerentanan Web

Frontend aplikasi pemindai kerentanan web yang modern dan responsif, dibangun dengan React dan TypeScript untuk memberikan pengalaman pengguna yang optimal dalam melakukan vulnerability scanning.

## 🎯 Gambaran Umum

Vulnity Frontend adalah antarmuka pengguna modern yang dirancang khusus untuk berinteraksi dengan sistem pemindai kerentanan web. Aplikasi ini menyediakan dashboard real-time, manajemen scan yang intuitif, dan visualisasi hasil vulnerability yang komprehensif dengan fokus pada user experience dan performance.

### ✨ Fitur Utama

#### 🏠 Dashboard Real-time
- **Statistik Live** dengan update otomatis via WebSocket
- **Visualisasi Data** menggunakan charts dan graphs interaktif
- **Monitoring Scan** dengan progress tracking real-time
- **Notifikasi Instant** untuk events penting

#### 🔐 Sistem Autentikasi Modern
- **JWT Authentication** dengan automatic token refresh
- **Protected Routes** dengan authentication guards
- **Session Management** yang aman dan persistent
- **Form Validation** yang komprehensif dengan real-time feedback

#### 🔍 Manajemen Scan Lengkap
- **Scan Configuration** dengan advanced settings
- **Multiple Scan Types** (SQL Injection, XSS, CSRF)
- **Real-time Progress** monitoring dengan WebSocket
- **Scan History** dan result management

#### 🛡️ Vulnerability Management
- **Detailed Vulnerability Views** dengan evidence dan proof
- **Risk Classification** (Critical, High, Medium, Low)
- **Status Management** (Open, Confirmed, False Positive, Fixed)
- **Export Capabilities** untuk reporting

#### 🎨 Modern UI/UX
- **Responsive Design** yang mobile-first
- **Dark/Light Theme** dengan smooth transitions
- **Accessibility-focused** components
- **Smooth Animations** dan micro-interactions

## 📁 Struktur Codebase

```
frontend/
├── public/                       # Static assets
│   ├── logo.svg                  # Application logo
│   └── vite.svg                  # Vite logo
├── src/                          # Source code
│   ├── components/               # Reusable UI components
│   │   ├── ui/                   # Base UI components (shadcn/ui style)
│   │   │   ├── button.tsx        # Button component dengan variants
│   │   │   ├── card.tsx          # Card layout component
│   │   │   ├── form.tsx          # Form components dengan validation
│   │   │   ├── input.tsx         # Input field components
│   │   │   ├── table.tsx         # Data table components
│   │   │   └── ...               # 30+ UI components
│   │   ├── scanner/              # Scanner-specific components
│   │   │   ├── scan-form.tsx     # Comprehensive scan configuration form
│   │   │   ├── scan-progress.tsx # Real-time scan progress display
│   │   │   └── scan-results.tsx  # Scan results visualization
│   │   └── dashboard/            # Dashboard components
│   │       ├── stats-cards.tsx   # Statistics display cards
│   │       ├── charts.tsx        # Data visualization charts
│   │       └── recent-scans.tsx  # Recent scans overview
│   ├── contexts/                 # React Context providers
│   │   └── auth-context.tsx      # Authentication state management
│   ├── hooks/                    # Custom React hooks
│   │   ├── use-websocket.ts      # WebSocket connection management
│   │   ├── use-toast.ts          # Toast notification system
│   │   └── use-api.ts            # API data fetching hooks
│   ├── lib/                      # Utility libraries
│   │   ├── api.ts                # Axios-based API client
│   │   ├── utils.ts              # General utility functions
│   │   └── websocket.ts          # WebSocket client implementation
│   ├── pages/                    # Page components
│   │   ├── dashboard.tsx         # Main dashboard page
│   │   ├── login.tsx             # Login page
│   │   ├── register.tsx          # Registration page
│   │   ├── scans.tsx             # Scan management page
│   │   └── vulnerabilities.tsx   # Vulnerability management page
│   ├── styles/                   # Global styles
│   │   ├── globals.css           # Global CSS styles
│   │   └── components.css        # Component-specific styles
│   ├── types/                    # TypeScript type definitions
│   │   ├── api.ts                # API response types
│   │   ├── auth.ts               # Authentication types
│   │   ├── scanner.ts            # Scanner-related types
│   │   └── vulnerability.ts      # Vulnerability data types
│   ├── utils/                    # Utility functions
│   │   ├── auth.ts               # Authentication utilities
│   │   ├── format.ts             # Data formatting functions
│   │   └── validation.ts         # Form validation helpers
│   ├── App.tsx                   # Main application component
│   ├── main.tsx                  # Application entry point
│   └── index.css                 # Main CSS file dengan TailwindCSS
├── package.json                  # Dependencies dan scripts
├── vite.config.ts                # Vite configuration
├── tsconfig.json                 # TypeScript configuration
├── tailwind.config.js            # TailwindCSS configuration
└── eslint.config.js              # ESLint configuration
```

## 🛠️ Technology Stack

### Core Framework & Build Tools
- **React 18** - Modern React dengan Concurrent Features
- **TypeScript 5** - Type safety dan developer experience yang superior
- **Vite 6** - Lightning-fast build tool dengan HMR
- **React Router DOM 6** - Client-side routing dengan modern API

### UI & Styling
- **TailwindCSS v4** - Utility-first CSS framework dengan custom theme
- **Radix UI** - Headless, accessible UI components
- **Lucide React** - Beautiful & consistent icon library
- **Framer Motion** - Production-ready motion library
- **next-themes** - Perfect dark/light mode dengan system preference

### Form & Validation
- **React Hook Form** - Performant forms dengan minimal re-renders
- **Zod** - TypeScript-first schema validation
- **@hookform/resolvers** - Seamless integration antara RHF dan Zod

### Data & API
- **Axios** - Promise-based HTTP client dengan interceptors
- **TanStack Query** - Powerful data synchronization (planned)
- **WebSocket API** - Real-time communication dengan backend

### Charts & Visualization
- **Recharts** - Composable charting library built on React components
- **D3.js** (via Recharts) - Data-driven document manipulation

### Development & Quality
- **ESLint** - Code linting dengan TypeScript support
- **Prettier** - Code formatting (configured via ESLint)
- **TypeScript ESLint** - TypeScript-specific linting rules

### Notifications & UX
- **Sonner** - Beautiful toast notifications
- **React Transition Group** - Transition components untuk smooth animations

## 🚀 Quick Start

### Prasyarat Sistem
- **Node.js 18+** (Direkomendasikan Node.js 20 LTS)
- **npm 9+** atau **yarn 1.22+** atau **pnpm 8+**
- **Git** untuk version control

### Instalasi & Setup

#### 1. Clone Repository
```bash
git clone <repository-url>
cd vulnity-kp/frontend
```

#### 2. Install Dependencies
```bash
# Menggunakan npm
npm install

# Atau menggunakan yarn
yarn install

# Atau menggunakan pnpm (recommended untuk performance)
pnpm install
```

#### 3. Setup Environment Variables
```bash
# Copy template environment file
cp .env.example .env.local

# Edit file .env.local dengan konfigurasi Anda
```

#### 4. Konfigurasi Environment
```env
# .env.local
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_BASE_URL=ws://localhost:8000
VITE_APP_NAME="Vulnity Scanner"
VITE_APP_VERSION="1.0.0"
```

#### 5. Jalankan Development Server
```bash
npm run dev
# atau
yarn dev
# atau
pnpm dev
```

Aplikasi akan berjalan di `http://localhost:5173` dengan hot module replacement aktif.

### 📦 Available Scripts

```bash
# Development server dengan HMR
npm run dev

# Build untuk production
npm run build

# Preview production build locally
npm run preview

# Lint code dengan ESLint
npm run lint

# Fix linting issues otomatis
npm run lint:fix

# Type checking dengan TypeScript
npm run type-check
```

## 🎨 Fitur-Fitur Utama

### Dashboard Real-time

Dashboard menyediakan overview komprehensif dari sistem scanning dengan update real-time:

#### Statistik Cards
- **Total Scans** - Jumlah scan yang telah dilakukan
- **Active Scans** - Scan yang sedang berjalan saat ini
- **Vulnerabilities Found** - Total vulnerability yang ditemukan
- **Critical Issues** - Vulnerability dengan risk level critical

#### Charts & Visualizations
- **Scan Trends** - Line chart menunjukkan tren scanning over time
- **Vulnerability Distribution** - Pie chart distribusi vulnerability berdasarkan risk level
- **Scan Types Performance** - Bar chart performa berbagai jenis scan
- **Recent Activity Timeline** - Timeline aktivitas terbaru

### Scan Management

#### Scan Configuration Form
Formulir konfigurasi scan yang comprehensive dengan validation real-time:

```typescript
// Contoh scan configuration
interface ScanConfig {
  target_url: string;           // URL target yang akan di-scan
  scan_name: string;            // Nama descriptive untuk scan
  description?: string;         // Deskripsi optional
  scan_types: string[];         // Array jenis scan: ['sql_injection', 'xss']
  max_depth: number;            // Kedalaman crawling maksimal (1-10)
  max_requests: number;         // Jumlah request maksimal (1-10000)
  request_delay: number;        // Delay antar request dalam detik (0.1-10)
}
```

#### Scan Types yang Tersedia
1. **SQL Injection Scanner**
   - Error-based detection
   - Boolean-based blind injection
   - Union-based injection
   - Time-based blind injection

2. **XSS Scanner**
   - Reflected XSS detection
   - Stored XSS detection
   - DOM-based XSS detection

3. **CSRF Scanner** (Coming Soon)
   - CSRF token validation
   - SameSite cookie analysis

#### Real-time Scan Progress
- **Progress Bar** dengan percentage completion
- **Current Phase** indicator (crawling, testing, analyzing)
- **Live Updates** via WebSocket connection
- **Estimated Time** remaining untuk completion

### Vulnerability Management

#### Vulnerability List View
- **Filtering** berdasarkan risk level, status, scan type
- **Sorting** berdasarkan tanggal, severity, confidence
- **Pagination** untuk handling large datasets
- **Search** functionality untuk quick finding

#### Detailed Vulnerability View
```typescript
interface VulnerabilityDetail {
  id: number;
  title: string;                    // Judul vulnerability
  description: string;              // Deskripsi detail
  vulnerability_type: string;       // Jenis vulnerability
  risk: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'confirmed' | 'false_positive' | 'fixed';
  endpoint: string;                 // URL endpoint yang vulnerable
  parameter: string;                // Parameter yang vulnerable
  method: string;                   // HTTP method
  payload: string;                  // Payload yang memicu vulnerability
  confidence: number;               // Confidence score (0.0 - 1.0)
  evidence: {                       // Evidence data
    request: string;                // HTTP request
    response: string;               // HTTP response
    proof: string;                  // Proof of concept
  };
  cwe_id: string;                   // CWE identifier
  owasp_category: string;           // OWASP Top 10 category
  remediation: string;              // Remediation advice
}
```

### Authentication System

#### Login Flow
```typescript
// Login dengan email/username dan password
const loginFlow = {
  1: "User input credentials",
  2: "Form validation dengan Zod schema",
  3: "API call ke /api/v1/auth/login",
  4: "JWT tokens disimpan di localStorage",
  5: "Redirect ke dashboard",
  6: "Setup automatic token refresh"
}
```

#### Protected Routes
```typescript
// Route protection dengan authentication guard
const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) return <LoadingSpinner />;
  if (!isAuthenticated) return <Navigate to="/login" />;

  return <>{children}</>;
};
```

#### Token Management
- **Automatic Refresh** - Token di-refresh otomatis sebelum expired
- **Secure Storage** - JWT tokens disimpan dengan secure practices
- **API Interceptors** - Automatic token attachment pada setiap request

## 🔌 Integrasi dengan Backend

### API Client Configuration

API client dibangun dengan Axios dan dilengkapi dengan interceptors untuk handling authentication dan error:

```typescript
// lib/api.ts - API Client Setup
import axios from 'axios';

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor untuk attach JWT token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor untuk handle token refresh
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      // Attempt token refresh
      await refreshToken();
      // Retry original request
      return apiClient.request(error.config);
    }
    return Promise.reject(error);
  }
);
```

### API Endpoints Integration

#### Authentication Endpoints
```typescript
// Authentication API calls
export const authApi = {
  login: (credentials: LoginRequest) =>
    apiClient.post<LoginResponse>('/api/v1/auth/login', credentials),

  register: (userData: RegisterRequest) =>
    apiClient.post<RegisterResponse>('/api/v1/auth/register', userData),

  logout: () =>
    apiClient.post('/api/v1/auth/logout'),

  refreshToken: () =>
    apiClient.post<TokenResponse>('/api/v1/auth/refresh'),

  getCurrentUser: () =>
    apiClient.get<UserProfile>('/api/v1/auth/me'),
};
```

#### Scan Management Endpoints
```typescript
// Scan API calls
export const scanApi = {
  startScan: (scanRequest: ScanRequest) =>
    apiClient.post<ScanResponse>('/api/v1/scan/start', scanRequest),

  getScans: (params?: ScanListParams) =>
    apiClient.get<ScanListResponse>('/api/v1/scan/', { params }),

  getScanById: (scanId: string) =>
    apiClient.get<ScanDetail>(`/api/v1/scan/${scanId}`),

  cancelScan: (scanId: string) =>
    apiClient.post(`/api/v1/scan/${scanId}/cancel`),

  deleteScan: (scanId: string) =>
    apiClient.delete(`/api/v1/scan/${scanId}`),
};
```

#### Vulnerability Management Endpoints
```typescript
// Vulnerability API calls
export const vulnerabilityApi = {
  getVulnerabilities: (params?: VulnListParams) =>
    apiClient.get<VulnListResponse>('/api/v1/vulnerability/', { params }),

  getVulnerabilityById: (vulnId: string) =>
    apiClient.get<VulnerabilityDetail>(`/api/v1/vulnerability/${vulnId}`),

  updateVulnerabilityStatus: (vulnId: string, status: VulnStatus) =>
    apiClient.patch(`/api/v1/vulnerability/${vulnId}`, { status }),

  exportVulnerabilities: (format: 'pdf' | 'csv' | 'json') =>
    apiClient.get(`/api/v1/vulnerability/export?format=${format}`, {
      responseType: 'blob'
    }),
};
```

### Error Handling & Response Management

#### Centralized Error Handling
```typescript
// Error handling dengan toast notifications
const handleApiError = (error: AxiosError) => {
  if (error.response) {
    // Server responded dengan error status
    const message = error.response.data?.detail || 'An error occurred';
    toast({
      title: "Error",
      description: message,
      variant: "destructive",
    });
  } else if (error.request) {
    // Request dibuat tapi tidak ada response
    toast({
      title: "Network Error",
      description: "Unable to connect to server. Please check your connection.",
      variant: "destructive",
    });
  } else {
    // Error dalam setup request
    toast({
      title: "Request Error",
      description: "Failed to make request. Please try again.",
      variant: "destructive",
    });
  }
};
```

#### Type-safe API Responses
```typescript
// Type definitions untuk API responses
interface ApiResponse<T> {
  data: T;
  message: string;
  status: 'success' | 'error';
}

interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

// Usage dengan TypeScript generics
const { data: scans } = await scanApi.getScans();
// scans is automatically typed as ScanListResponse
```

### Real-time Communication Setup

#### WebSocket Integration
```typescript
// hooks/use-websocket.ts - WebSocket hook
export const useWebSocket = (url: string) => {
  const [socket, setSocket] = useState<WebSocket | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected'>('disconnected');
  const [lastMessage, setLastMessage] = useState<any>(null);

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    const wsUrl = `${url}?token=${token}`;

    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      setConnectionStatus('connected');
      setSocket(ws);
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setLastMessage(data);
    };

    ws.onclose = () => {
      setConnectionStatus('disconnected');
      setSocket(null);
    };

    return () => {
      ws.close();
    };
  }, [url]);

  const sendMessage = useCallback((message: any) => {
    if (socket && connectionStatus === 'connected') {
      socket.send(JSON.stringify(message));
    }
  }, [socket, connectionStatus]);

  return { connectionStatus, lastMessage, sendMessage };
};
```

#### Dashboard Real-time Updates
```typescript
// Dashboard component dengan WebSocket integration
const Dashboard = () => {
  const { lastMessage } = useWebSocket(`${WS_BASE_URL}/ws/dashboard`);
  const [stats, setStats] = useState<DashboardStats | null>(null);

  useEffect(() => {
    if (lastMessage?.type === 'dashboard_update') {
      setStats(lastMessage.data);
    }
  }, [lastMessage]);

  return (
    <div className="dashboard">
      <StatsCards stats={stats} />
      <ChartsSection stats={stats} />
      <RecentActivity />
    </div>
  );
};
```

## 🧩 Component Documentation

### UI Components (shadcn/ui)

#### Button Component
```typescript
// components/ui/button.tsx
interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link';
  size?: 'default' | 'sm' | 'lg' | 'icon';
  asChild?: boolean;
}

// Usage examples
<Button variant="default" size="lg">Primary Action</Button>
<Button variant="outline" size="sm">Secondary Action</Button>
<Button variant="destructive">Delete</Button>
```

#### Card Component
```typescript
// components/ui/card.tsx
const Card = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn("rounded-lg border bg-card text-card-foreground shadow-sm", className)}
      {...props}
    />
  )
);

// Usage dengan sub-components
<Card>
  <CardHeader>
    <CardTitle>Scan Results</CardTitle>
    <CardDescription>Latest vulnerability scan results</CardDescription>
  </CardHeader>
  <CardContent>
    <ScanResultsTable />
  </CardContent>
  <CardFooter>
    <Button>View Details</Button>
  </CardFooter>
</Card>
```

#### Form Components
```typescript
// Form dengan React Hook Form + Zod validation
const ScanForm = () => {
  const form = useForm<ScanFormValues>({
    resolver: zodResolver(scanFormSchema),
    defaultValues: {
      target_url: '',
      scan_name: '',
      scan_types: ['sql_injection'],
    },
  });

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)}>
        <FormField
          control={form.control}
          name="target_url"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Target URL</FormLabel>
              <FormControl>
                <Input placeholder="https://example.com" {...field} />
              </FormControl>
              <FormDescription>
                The URL of the website to scan
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button type="submit">Start Scan</Button>
      </form>
    </Form>
  );
};
```

### Custom Hooks

#### useAuth Hook
```typescript
// hooks/use-auth.ts
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

// Usage dalam component
const Dashboard = () => {
  const { user, isAuthenticated, logout } = useAuth();

  if (!isAuthenticated) {
    return <Navigate to="/login" />;
  }

  return <div>Welcome, {user?.username}!</div>;
};
```

#### useToast Hook
```typescript
// hooks/use-toast.ts
export const useToast = () => {
  const { toast } = useContext(ToastContext);

  return {
    toast: (props: ToastProps) => {
      // Show toast notification
      toast(props);
    },
    success: (message: string) => {
      toast({ title: "Success", description: message });
    },
    error: (message: string) => {
      toast({ title: "Error", description: message, variant: "destructive" });
    },
  };
};
```

## 🏗️ Build dan Deployment

### Development Build
```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Development server akan berjalan di http://localhost:5173
# dengan hot module replacement dan fast refresh aktif
```

### Production Build
```bash
# Build untuk production
npm run build

# Output akan tersimpan di folder 'dist/'
# Files akan di-minify dan optimized untuk production

# Preview production build locally
npm run preview
```

### Build Configuration (Vite)
```typescript
// vite.config.ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

export default defineConfig({
  plugins: [
    react(),
    tailwindcss()
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom'],
          ui: ['@radix-ui/react-dialog', '@radix-ui/react-dropdown-menu'],
          charts: ['recharts'],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
})
```

### Deployment ke Production

#### 1. Static Hosting (Netlify, Vercel)
```bash
# Build production
npm run build

# Deploy folder 'dist/' ke static hosting
# Pastikan untuk setup redirects untuk SPA routing
```

#### 2. Docker Deployment
```dockerfile
# Dockerfile
FROM node:18-alpine as builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

#### 3. Environment Variables untuk Production
```env
# .env.production
VITE_API_BASE_URL=https://api.yourdomain.com
VITE_WS_BASE_URL=wss://api.yourdomain.com
VITE_APP_NAME="Vulnity Scanner"
VITE_APP_VERSION="1.0.0"
VITE_ENVIRONMENT="production"
```

## 🧪 Testing Strategy

### Testing Framework Setup
```bash
# Install testing dependencies (planned)
npm install --save-dev @testing-library/react @testing-library/jest-dom vitest jsdom

# Test configuration akan menggunakan Vitest untuk unit tests
# dan React Testing Library untuk component testing
```

### Recommended Testing Structure
```
src/
├── components/
│   ├── ui/
│   │   ├── button.tsx
│   │   └── __tests__/
│   │       └── button.test.tsx
│   └── scanner/
│       ├── scan-form.tsx
│       └── __tests__/
│           └── scan-form.test.tsx
├── hooks/
│   ├── use-auth.ts
│   └── __tests__/
│       └── use-auth.test.ts
└── utils/
    ├── api.ts
    └── __tests__/
        └── api.test.ts
```

### Example Test Cases
```typescript
// components/ui/__tests__/button.test.tsx
import { render, screen } from '@testing-library/react'
import { Button } from '../button'

describe('Button Component', () => {
  it('renders with correct text', () => {
    render(<Button>Click me</Button>)
    expect(screen.getByRole('button')).toHaveTextContent('Click me')
  })

  it('applies correct variant classes', () => {
    render(<Button variant="destructive">Delete</Button>)
    expect(screen.getByRole('button')).toHaveClass('bg-destructive')
  })
})
```

### Running Tests
```bash
# Run all tests
npm run test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage

# Run specific test file
npm run test button.test.tsx
```

## 📋 Development Guidelines

### Code Style & Standards

#### TypeScript Best Practices
```typescript
// ✅ Good: Explicit interface definitions
interface ScanFormProps {
  onSuccess?: (scanId: string) => void;
  onCancel?: () => void;
  isModal?: boolean;
}

// ✅ Good: Proper error handling
const handleSubmit = async (data: FormData) => {
  try {
    const result = await api.submitScan(data);
    onSuccess?.(result.scanId);
  } catch (error) {
    if (error instanceof ApiError) {
      showError(error.message);
    } else {
      showError('An unexpected error occurred');
    }
  }
};

// ❌ Avoid: Any types
const handleData = (data: any) => { ... }

// ✅ Good: Proper typing
const handleData = (data: ScanData) => { ... }
```

#### Component Structure
```typescript
// Recommended component structure
import React from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';

// Types & Schemas
const formSchema = z.object({
  // schema definition
});

type FormValues = z.infer<typeof formSchema>;

interface ComponentProps {
  // props definition
}

// Component
export const MyComponent: React.FC<ComponentProps> = ({
  prop1,
  prop2
}) => {
  // Hooks
  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
  });

  // Event handlers
  const handleSubmit = (values: FormValues) => {
    // implementation
  };

  // Render
  return (
    <div>
      {/* JSX */}
    </div>
  );
};
```

#### File Naming Conventions
- **Components**: PascalCase (`ScanForm.tsx`, `DashboardStats.tsx`)
- **Hooks**: camelCase dengan prefix 'use' (`useAuth.ts`, `useWebSocket.ts`)
- **Utils**: camelCase (`formatDate.ts`, `apiClient.ts`)
- **Types**: camelCase (`scanTypes.ts`, `apiTypes.ts`)
- **Constants**: UPPER_SNAKE_CASE (`API_ENDPOINTS.ts`)

#### Import Organization
```typescript
// 1. React imports
import React, { useState, useEffect } from 'react';

// 2. Third-party libraries
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';

// 3. UI components
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

// 4. Internal components
import { ScanProgress } from '@/components/scanner/scan-progress';

// 5. Hooks
import { useAuth } from '@/hooks/use-auth';
import { useToast } from '@/hooks/use-toast';

// 6. Utils & API
import { scanApi } from '@/lib/api';
import { formatDate } from '@/utils/format';

// 7. Types
import type { ScanRequest } from '@/types/api';
```

### Performance Best Practices

#### Component Optimization
```typescript
// ✅ Good: Memoize expensive calculations
const ExpensiveComponent = ({ data }: { data: LargeDataSet }) => {
  const processedData = useMemo(() => {
    return processLargeDataSet(data);
  }, [data]);

  return <div>{processedData}</div>;
};

// ✅ Good: Memoize callbacks
const ParentComponent = () => {
  const handleClick = useCallback((id: string) => {
    // handle click
  }, []);

  return <ChildComponent onClick={handleClick} />;
};

// ✅ Good: Lazy loading untuk large components
const LazyDashboard = lazy(() => import('@/pages/dashboard'));
```

#### Bundle Optimization
```typescript
// ✅ Good: Dynamic imports untuk code splitting
const loadChartComponent = () => import('@/components/charts/advanced-chart');

// ✅ Good: Tree shaking friendly imports
import { Button } from '@/components/ui/button';
// ❌ Avoid: Barrel imports yang tidak tree-shakeable
import { Button, Card, Input } from '@/components/ui';
```

## 🔧 Troubleshooting

### Common Issues & Solutions

#### 1. Build Errors

**Error: "Cannot resolve module '@/components/ui/button'"**
```bash
# Solution: Check path alias configuration
# Pastikan vite.config.ts memiliki alias configuration:
resolve: {
  alias: {
    '@': path.resolve(__dirname, './src'),
  },
}
```

**Error: "Module not found: Can't resolve 'react-router-dom'"**
```bash
# Solution: Install missing dependency
npm install react-router-dom
npm install --save-dev @types/react-router-dom
```

#### 2. Runtime Errors

**Error: "useAuth must be used within AuthProvider"**
```typescript
// Solution: Wrap app dengan AuthProvider
// main.tsx
import { AuthProvider } from '@/contexts/auth-context';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <AuthProvider>
    <App />
  </AuthProvider>
);
```

**Error: "WebSocket connection failed"**
```typescript
// Solution: Check WebSocket URL dan backend status
// Pastikan backend WebSocket server berjalan di port yang benar
const WS_URL = import.meta.env.VITE_WS_BASE_URL || 'ws://localhost:8000';
```

#### 3. Styling Issues

**Error: "TailwindCSS classes not working"**
```bash
# Solution: Check TailwindCSS configuration
# Pastikan tailwind.config.js memiliki content paths yang benar:
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  // ...
}
```

**Error: "Dark mode not switching"**
```typescript
// Solution: Check theme provider setup
// Pastikan ThemeProvider di-wrap dengan benar
import { ThemeProvider } from 'next-themes';

<ThemeProvider attribute="class" defaultTheme="system">
  <App />
</ThemeProvider>
```

#### 4. API Integration Issues

**Error: "CORS policy error"**
```typescript
// Solution: Configure proxy di vite.config.ts
server: {
  proxy: {
    '/api': {
      target: 'http://localhost:8000',
      changeOrigin: true,
    },
  },
}
```

**Error: "401 Unauthorized on API calls"**
```typescript
// Solution: Check token storage dan refresh logic
// Pastikan token disimpan dengan benar setelah login
localStorage.setItem('access_token', response.data.access_token);

// Dan pastikan interceptor menambahkan token ke headers
config.headers.Authorization = `Bearer ${token}`;
```

### Debug Mode

#### Enable Debug Logging
```typescript
// lib/api.ts - Add request/response logging
apiClient.interceptors.request.use(
  (config) => {
    if (import.meta.env.DEV) {
      console.log('API Request:', config);
    }
    return config;
  }
);

apiClient.interceptors.response.use(
  (response) => {
    if (import.meta.env.DEV) {
      console.log('API Response:', response);
    }
    return response;
  }
);
```

#### React DevTools
```bash
# Install React DevTools browser extension
# untuk debugging component state dan props

# Install Redux DevTools jika menggunakan Redux
# untuk debugging application state
```

### Performance Debugging

#### Bundle Analysis
```bash
# Analyze bundle size
npm run build
npx vite-bundle-analyzer dist

# Check untuk large dependencies dan optimize imports
```

#### Memory Leaks
```typescript
// Check untuk memory leaks di useEffect
useEffect(() => {
  const subscription = someObservable.subscribe();

  // ✅ Good: Cleanup subscription
  return () => {
    subscription.unsubscribe();
  };
}, []);

// ✅ Good: Cleanup WebSocket connections
useEffect(() => {
  const ws = new WebSocket(url);

  return () => {
    ws.close();
  };
}, []);
```

## 📚 Resources & References

### Documentation Links
- **React Documentation**: https://react.dev/
- **TypeScript Handbook**: https://www.typescriptlang.org/docs/
- **Vite Guide**: https://vitejs.dev/guide/
- **TailwindCSS Documentation**: https://tailwindcss.com/docs
- **React Router**: https://reactrouter.com/
- **React Hook Form**: https://react-hook-form.com/
- **Zod Documentation**: https://zod.dev/

### UI & Design Resources
- **Radix UI**: https://www.radix-ui.com/
- **shadcn/ui**: https://ui.shadcn.com/
- **Lucide Icons**: https://lucide.dev/
- **Recharts**: https://recharts.org/

### Development Tools
- **ESLint**: https://eslint.org/
- **Prettier**: https://prettier.io/
- **Vitest**: https://vitest.dev/
- **React Testing Library**: https://testing-library.com/docs/react-testing-library/intro/

## 🤝 Contributing

### Development Workflow
1. **Fork repository** dan buat branch baru untuk feature
2. **Follow code style** dan naming conventions yang ada
3. **Add comprehensive tests** untuk semua new features
4. **Update documentation** sesuai dengan perubahan
5. **Submit pull request** dengan deskripsi yang jelas

### Code Review Checklist
- [ ] Code mengikuti TypeScript best practices
- [ ] Components memiliki proper props typing
- [ ] Error handling yang adequate
- [ ] Performance considerations (memoization, lazy loading)
- [ ] Accessibility compliance
- [ ] Responsive design implementation
- [ ] Tests coverage untuk new features
- [ ] Documentation telah diupdate

### Commit Message Convention
```bash
# Format: type(scope): description
feat(auth): add JWT token refresh mechanism
fix(scan): resolve WebSocket connection issues
docs(readme): update API integration examples
style(ui): improve button component variants
refactor(hooks): optimize useAuth hook performance
test(components): add unit tests for ScanForm
```

## 📄 License

MIT License - Lihat file LICENSE untuk detail lengkap.

---

**Vulnity Frontend** - Dikembangkan dengan ❤️ untuk pengalaman pengguna yang optimal dalam vulnerability scanning.
