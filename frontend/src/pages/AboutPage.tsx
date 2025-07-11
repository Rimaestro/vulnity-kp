import React from 'react'
import { Shield, Target, TrendingUp, CheckCircle } from 'lucide-react'

export const AboutPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">About Vulnity Scanner</h1>
        <p className="text-gray-600">Web vulnerability assessment tool based on empirical DVWA testing</p>
      </div>

      {/* Overview */}
      <div className="card">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Project Overview</h2>
        <p className="text-gray-600 mb-4">
          Vulnity Scanner is a comprehensive web vulnerability assessment tool developed as part of a 
          Kuliah Praktik (KP) project. The scanner is based on extensive analysis and testing of 
          SQL injection vulnerabilities using DVWA (Damn Vulnerable Web Application) as a validation platform.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="text-center p-4 bg-blue-50 rounded-lg">
            <Target className="h-8 w-8 text-blue-600 mx-auto mb-2" />
            <h3 className="font-medium text-blue-900">70% Success Rate</h3>
            <p className="text-sm text-blue-700">Empirically validated payload effectiveness</p>
          </div>
          <div className="text-center p-4 bg-green-50 rounded-lg">
            <CheckCircle className="h-8 w-8 text-green-600 mx-auto mb-2" />
            <h3 className="font-medium text-green-900">10 Payloads Tested</h3>
            <p className="text-sm text-green-700">Comprehensive SQL injection coverage</p>
          </div>
          <div className="text-center p-4 bg-purple-50 rounded-lg">
            <Shield className="h-8 w-8 text-purple-600 mx-auto mb-2" />
            <h3 className="font-medium text-purple-900">DVWA Validated</h3>
            <p className="text-sm text-purple-700">Real-world testing environment</p>
          </div>
        </div>
      </div>

      {/* Technical Details */}
      <div className="card">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Technical Implementation</h2>
        <div className="space-y-4">
          <div>
            <h3 className="font-medium text-gray-900 mb-2">Backend Technology</h3>
            <ul className="list-disc list-inside text-sm text-gray-600 space-y-1">
              <li>Python with FastAPI framework</li>
              <li>SQLite database for scan results</li>
              <li>Requests library for HTTP scanning</li>
              <li>Pattern-based vulnerability detection</li>
            </ul>
          </div>
          
          <div>
            <h3 className="font-medium text-gray-900 mb-2">Frontend Technology</h3>
            <ul className="list-disc list-inside text-sm text-gray-600 space-y-1">
              <li>React 18 with TypeScript</li>
              <li>Vite for fast development and building</li>
              <li>Tailwind CSS for styling</li>
              <li>React Query for API state management</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Research Findings */}
      <div className="card">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Research Findings</h2>
        <div className="space-y-4">
          <div>
            <h3 className="font-medium text-gray-900 mb-2">Payload Success Analysis</h3>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <h4 className="font-medium text-green-700 mb-1">Successful Payloads (7/10)</h4>
                <ul className="text-gray-600 space-y-1">
                  <li>• Boolean-based: <code>1' OR '1'='1</code></li>
                  <li>• Comment-based: <code>1' OR 1=1#</code></li>
                  <li>• Union-based: <code>1' UNION SELECT 1,2#</code></li>
                  <li>• System info: <code>1' UNION SELECT user(),version()#</code></li>
                  <li>• Time-based: <code>1' AND SLEEP(5)#</code></li>
                  <li>• Blind true: <code>1' AND 1=1#</code></li>
                  <li>• Blind false: <code>1' AND 1=2#</code></li>
                </ul>
              </div>
              <div>
                <h4 className="font-medium text-red-700 mb-1">Failed Payloads (3/10)</h4>
                <ul className="text-gray-600 space-y-1">
                  <li>• Double dash syntax errors</li>
                  <li>• Information disclosure via errors</li>
                  <li>• File path and function exposure</li>
                </ul>
              </div>
            </div>
          </div>
          
          <div>
            <h3 className="font-medium text-gray-900 mb-2">Key Discoveries</h3>
            <ul className="list-disc list-inside text-sm text-gray-600 space-y-1">
              <li>Hash (#) comment syntax: 100% success rate</li>
              <li>Double dash (--) comment syntax: 0% success rate</li>
              <li>MariaDB 10.4.32 specific behavior patterns</li>
              <li>Critical information extraction capabilities</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Development Status */}
      <div className="card">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Development Status</h2>
        <div className="space-y-3">
          <div className="flex items-center space-x-3">
            <CheckCircle className="h-5 w-5 text-green-600" />
            <span className="text-sm text-gray-900">Backend scanner engine implementation</span>
          </div>
          <div className="flex items-center space-x-3">
            <CheckCircle className="h-5 w-5 text-green-600" />
            <span className="text-sm text-gray-900">DVWA validation and testing</span>
          </div>
          <div className="flex items-center space-x-3">
            <CheckCircle className="h-5 w-5 text-green-600" />
            <span className="text-sm text-gray-900">API endpoints and documentation</span>
          </div>
          <div className="flex items-center space-x-3">
            <TrendingUp className="h-5 w-5 text-blue-600" />
            <span className="text-sm text-gray-900">Frontend interface development (in progress)</span>
          </div>
        </div>
      </div>
    </div>
  )
}
