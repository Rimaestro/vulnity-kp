import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertCircle, Play, Loader } from 'lucide-react'
import { scanService } from '../services/scanService'
import { ScanRequest } from '../types/scan'

export const ScanPage: React.FC = () => {
  const [formData, setFormData] = useState<ScanRequest>({
    targetUrl: 'http://localhost/dvwa/vulnerabilities/sqli/',
    username: 'admin',
    password: 'password',
    scanType: 'sql_injection'
  })
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target
    setFormData(prev => ({
      ...prev,
      [name]: value
    }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError(null)

    try {
      const result = await scanService.startScan(formData)
      // Redirect to results page with scan ID
      navigate(`/results/${result.id}`)
    } catch (err: any) {
      setError(err.message || 'Failed to start scan')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Start Vulnerability Scan</h1>
        <p className="text-gray-600">Configure and launch SQL injection vulnerability assessment</p>
      </div>

      {error && (
        <div className="card">
          <div className="flex items-center space-x-3 p-4 bg-red-50 border border-red-200 rounded-lg">
            <AlertCircle className="h-5 w-5 text-red-600" />
            <div>
              <h3 className="font-medium text-red-900">Scan Failed</h3>
              <p className="text-sm text-red-700">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Scan Form */}
      <div className="card">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Scan Configuration</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Target URL *
            </label>
            <input
              type="url"
              name="targetUrl"
              value={formData.targetUrl}
              onChange={handleInputChange}
              placeholder="http://localhost/dvwa/vulnerabilities/sqli/"
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              required
            />
            <p className="text-sm text-gray-500 mt-1">
              Enter the URL of the web application to scan
            </p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Username (Optional)
              </label>
              <input
                type="text"
                name="username"
                value={formData.username}
                onChange={handleInputChange}
                placeholder="admin"
                className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Password (Optional)
              </label>
              <input
                type="password"
                name="password"
                value={formData.password}
                onChange={handleInputChange}
                placeholder="password"
                className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>

          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-600">
              <p>• Scan will test for SQL injection vulnerabilities</p>
              <p>• Based on DVWA analysis with 70% success rate</p>
              <p>• Authentication credentials are optional but recommended</p>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="flex items-center space-x-2 px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <>
                  <Loader className="h-4 w-4 animate-spin" />
                  <span>Starting Scan...</span>
                </>
              ) : (
                <>
                  <Play className="h-4 w-4" />
                  <span>Start Scan</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Scanner Information */}
      <div className="card">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Scanner Information</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 bg-blue-50 rounded-lg">
            <h3 className="font-medium text-blue-900">SQL Injection Detection</h3>
            <p className="text-sm text-blue-700 mt-1">
              Tests 5 types: Boolean, Union, Time-based, Error-based, Blind Boolean
            </p>
          </div>

          <div className="p-4 bg-green-50 rounded-lg">
            <h3 className="font-medium text-green-900">70% Success Rate</h3>
            <p className="text-sm text-green-700 mt-1">
              Based on empirical testing with 10 validated payloads
            </p>
          </div>

          <div className="p-4 bg-purple-50 rounded-lg">
            <h3 className="font-medium text-purple-900">DVWA Optimized</h3>
            <p className="text-sm text-purple-700 mt-1">
              Specifically tuned for DVWA and similar applications
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
