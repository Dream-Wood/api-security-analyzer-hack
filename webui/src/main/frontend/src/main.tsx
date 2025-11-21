import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './i18n/config' // Import i18n configuration
import './styles/App.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
