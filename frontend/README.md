# Vulnity Scanner Frontend

React + TypeScript + Vite frontend for Vulnity Web Vulnerability Scanner.

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ 
- npm or yarn

### Installation

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

## 🛠️ Development

### Available Scripts

- `npm run dev` - Start development server (http://localhost:5173)
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint

### Project Structure

```
src/
├── components/          # Reusable UI components
│   └── layout/         # Layout components (Header, Sidebar)
├── pages/              # Page components
├── services/           # API service layer
├── types/              # TypeScript type definitions
├── utils/              # Utility functions
└── styles/             # CSS and styling
```

## 🎯 Features

- **Modern React**: React 18 with hooks and functional components
- **TypeScript**: Full type safety and better developer experience
- **Vite**: Fast development and building
- **Tailwind CSS**: Utility-first CSS framework
- **React Router**: Client-side routing
- **React Query**: Data fetching and state management
- **Responsive Design**: Mobile-friendly interface

## 🔗 Backend Integration

The frontend communicates with the FastAPI backend through:
- API proxy configuration in Vite
- Axios HTTP client with interceptors
- TypeScript interfaces for API responses
- React Query for data fetching and caching

## 📱 Pages

- **Dashboard**: Overview and quick actions
- **Scan**: Configure and start vulnerability scans
- **Results**: View scan results and reports
- **About**: Project information and documentation

## 🎨 UI Components

- Responsive layout with sidebar navigation
- Professional styling with Tailwind CSS
- Loading states and error handling
- Severity-based color coding for vulnerabilities

## 🚧 Development Status

Currently in development as part of KP project. Backend integration will be implemented after backend completion.

## 🤝 Contributing

This is a KP (Kuliah Praktik) project. For development:

1. Focus on backend implementation first
2. Frontend will be connected after backend is stable
3. Follow TypeScript best practices
4. Use existing component patterns
