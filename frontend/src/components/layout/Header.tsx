import React from 'react'
import { Shield } from 'lucide-react'

export const Header: React.FC = () => {
  return (
    <header className="bg-white shadow-sm border-b border-gray-200">
      <div className="px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-blue-600" />
            <div>
              <h1 className="text-xl font-bold text-gray-900">Vulnity Scanner</h1>
              <p className="text-sm text-gray-500">Web Vulnerability Assessment Tool</p>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <span className="text-sm text-gray-600">
              Based on DVWA Analysis • 70% Success Rate
            </span>
            <div className="text-sm text-gray-500">
              Demo Mode - No Login Required
            </div>
          </div>
        </div>
      </div>
    </header>
  )
}
