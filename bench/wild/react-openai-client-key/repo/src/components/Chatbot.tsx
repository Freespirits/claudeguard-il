import React, { useState } from 'react';
import { sendMessageToOpenAI } from '../services/openai';
import type { ChatMessage } from '../services/openai';
import './Chatbot.css';

const Chatbot: React.FC = () => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: 'system',
      content: 'You are a helpful assistant created by Sergie Code, a software engineer who teaches programming on YouTube.'
    }
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSendMessage = async () => {
    if (!inputMessage.trim()) return;

    const userMessage: ChatMessage = {
      role: 'user',
      content: inputMessage
    };

    const newMessages = [...messages, userMessage];
    setMessages(newMessages);
    setInputMessage('');
    setIsLoading(true);

    try {
      const response = await sendMessageToOpenAI(newMessages);
      const assistantMessage: ChatMessage = {
        role: 'assistant',
        content: response
      };

      setMessages([...newMessages, assistantMessage]);
    } catch (error) {
      console.error('Error:', error);
      const errorMessage: ChatMessage = {
        role: 'assistant',
        content: 'Sorry, I encountered an error. Please try again.'
      };
      setMessages([...newMessages, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  return (
    <div className="chatbot-container">
      <div className="chatbot-header">
        <h2>AI Chatbot</h2>
        <p>Created by <strong>Sergie Code</strong></p>
      </div>
      
      <div className="chatbot-messages">
        {messages
          .filter(msg => msg.role !== 'system')
          .map((message, index) => (
            <div key={index} className={`message ${message.role}`}>
              <div className="message-content">
                {message.content}
              </div>
            </div>
          ))}
        {isLoading && (
          <div className="message assistant">
            <div className="message-content">
              <div className="typing-indicator">
                <span></span>
                <span></span>
                <span></span>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="chatbot-input">
        <textarea
          value={inputMessage}
          onChange={(e) => setInputMessage(e.target.value)}
          onKeyPress={handleKeyPress}
          placeholder="Type your message here..."
          disabled={isLoading}
          rows={3}
        />
        <button 
          onClick={handleSendMessage}
          disabled={isLoading || !inputMessage.trim()}
        >
          Send
        </button>
      </div>
    </div>
  );
};

export default Chatbot;
