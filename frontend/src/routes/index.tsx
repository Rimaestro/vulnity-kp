import { Routes as RouterRoutes, Route } from 'react-router-dom'
import Dashboard from '../pages/Dashboard'

const Routes = () => {
  return (
    <RouterRoutes>
      <Route path="/" element={<Dashboard />} />
    </RouterRoutes>
  )
}

export default Routes 