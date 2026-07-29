import Chatbot from './components/Chatbot'
import './App.css'

function App() {
  return (
    <div className="App">
      <header className="app-header">
        <h1>OpenAI Chatbot</h1>
        <div className="creator-info">
          <p>Created by <strong>Sergie Code</strong> - Software Engineer & Programming Teacher</p>
          <div className="social-links">
            <a href="https://www.youtube.com/@SergieCode" target="_blank" rel="noopener noreferrer">
              📽️ YouTube
            </a>
            <a href="https://www.instagram.com/sergiecode" target="_blank" rel="noopener noreferrer">
              📸 Instagram
            </a>
            <a href="https://www.linkedin.com/in/sergiecode/" target="_blank" rel="noopener noreferrer">
              🧑🏼‍💻 LinkedIn
            </a>
            <a href="https://github.com/sergiecode" target="_blank" rel="noopener noreferrer">
              😺 GitHub
            </a>
          </div>
        </div>
      </header>
      
      <main>
        <Chatbot />
      </main>
    </div>
  )
}

export default App
