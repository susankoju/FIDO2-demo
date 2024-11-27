import { useState } from 'react'
import axios from 'axios'
import {
  startRegistration,
  startAuthentication,
} from '@simplewebauthn/browser';
import './App.css'

function App() {
  const [username, setUsername] = useState('');
  const [message, setMessage] = useState('')

  const handleRegister = async () => {
    try {
      const { data: options } = await axios.post('http://localhost:4000/registration-initiate', {
        username
      })
      console.log('Registration initiated', { options });

      const attestationResponse = await startRegistration({
        optionsJSON: options,
        useAutoRegister: false,
      });
      console.log({ attestationResponse });

      const { data } = await axios.post('http://localhost:4000/registration-complete', {
        username,
        attestationResponse
      })

      console.log('Registration complete', { data });

      if (data.success) {
        setMessage('Registration successful!')
      }
    } catch (err) {
      setMessage(`Error: ${err.response?.data?.error || err.message}`)
    }
  }

  const handleLogin = async () => {
    try {
      const { data: options } = await axios.post('http://localhost:4000/login-initiate', {
        username
      })
      console.log('Login initiated', { options });

      const authenticationResponse = await startAuthentication({
        optionsJSON: options,
      });
      console.log({ authenticationResponse });

      const { data } = await axios.post('http://localhost:4000/login-complete', {
        username,
        authenticationResponse
      })

      console.log('Login complete', { data });

      if (data.success) {
        setMessage('Login successful!')
      }
    } catch (err) {
      setMessage(`Error: ${err.response?.data?.error || err.message}`)
    }
  }

  return (
    <>
      <div style={{ padding: '5rem' }}>
        <h1>FIDO2 Authentication</h1>
        <br />
        <input
          type="text"
          placeholder='Enter username'
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          style={{ padding: '10px', marginBottom: '10px' }}
        ></input>

        <div>
          <button style={{ padding: '10px', marginRight: '10px' }} onClick={handleRegister}>
            Register
          </button>
          <button style={{ padding: '10px', marginRight: '10px' }} onClick={handleLogin}>
            Login
          </button>
          {message && <p>{message}</p>}
        </div>
      </div>
    </>
  )
}

export default App
