import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../App";
import axios from "axios";
import "./ChatPage.css";
import { FiSend, FiLogOut, FiUser } from "react-icons/fi";

interface User {
  _id: string;
  id?: string;
  uuid?: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  name?: string;
  username?: string;
  role?: string;
  token?: string;
}

interface Message {
  _id: string;
  authorId: string;
  authorName: string;
  content: string;
  timestamp: string;
  isUser: boolean;
}

const ChatPage: React.FC = () => {
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const { logout } = useAuth();
  const pollingInterval = useRef<number | undefined>(undefined);

  const currentUser = JSON.parse(
    localStorage.getItem("user") || "null"
  ) as User | null;
  console.log("Current user email:", currentUser?.email); // Debug log

  // Fetch messages from server
  const fetchMessages = async () => {
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        navigate("/login");
        return;
      }

      const response = await axios.get("http://localhost:3000/messages", {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.data) {
        const currentUserEmail = currentUser?.email;
        const formattedMessages = response.data.map((msg: any) => {
          const isCurrentUser = currentUserEmail
            ? msg.authorEmail === currentUserEmail
            : false;
          return {
            ...msg,
            isUser: isCurrentUser,
          };
        });
        setMessages(formattedMessages);
      }
    } catch (err) {
      console.error("Error fetching messages:", err);
      setError("Napaka pri pridobivanju sporočil");
    }
  };

  // Set up polling
  useEffect(() => {
    // Initial fetch
    fetchMessages();

    // Set up interval for polling every 3 seconds
    pollingInterval.current = setInterval(() => {
      fetchMessages();
    }, 3000);

    // Clean up interval on component unmount
    return () => {
      if (pollingInterval.current) {
        clearInterval(pollingInterval.current);
      }
    };
  }, []);

  // Track if we should auto-scroll
  const shouldAutoScroll = useRef(true);
  const messagesContainerRef = useRef<HTMLDivElement>(null);

  // Handle scroll events
  const handleScroll = () => {
    if (!messagesContainerRef.current) return;

    const { scrollTop, scrollHeight, clientHeight } =
      messagesContainerRef.current;
    const isNearBottom = scrollHeight - (scrollTop + clientHeight) < 100;
    shouldAutoScroll.current = isNearBottom;
  };

  useEffect(() => {
    if (shouldAutoScroll.current) {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages]);

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!message.trim()) return;

    try {
      setIsLoading(true);
      const token = localStorage.getItem("token");
      const user = JSON.parse(localStorage.getItem("user") || "null");

      if (!token || !user) {
        navigate("/login");
        return;
      }

      console.log("Current user data:", user);

      const messageData = {
        authorId: user.id || user._id || user.uuid,
        authorEmail: user.email,
        authorName: user.firstName,
        content: message,
        timestamp: new Date().toISOString(),
      };

      console.log("Sending message with data:", messageData); // Debug log

      await axios.post("http://localhost:3000/postMessage", messageData, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });

      setMessage("");
      // Fetch updated messages after sending
      await fetchMessages();
    } catch (err) {
      console.error("Error sending message:", err);
      setError("Napaka pri pošiljanju sporočila");
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="chat-page">
      <header className="chat-header">
        <div className="header-content">
          <h1>Klepetalnica</h1>
          {currentUser?.email && (
            <div className="welcome-message">
              Welcome back,{" "}
              <span className="user-email">{currentUser.email}</span>
            </div>
          )}
        </div>
        <div className="header-buttons">
          <button
            onClick={() => navigate("/profile")}
            className="profile-button"
            title="Profil"
          >
            <FiUser size={20} />
          </button>
          <button
            onClick={handleLogout}
            className="logout-button"
            title="Odjava"
          >
            <FiLogOut size={20} />
          </button>
        </div>
      </header>

      <div
        className="chat-messages"
        ref={messagesContainerRef}
        onScroll={handleScroll}
      >
        {error && <div className="error-message">{error}</div>}
        {isLoading && <div>Nalagam...</div>}
        {messages.map((msg) => (
          <div
            key={msg._id}
            className={`message-container ${msg.isUser ? "user" : "other"}`}
          >
            {!msg.isUser && (
              <div className="message-avatar">
                {msg.authorName.charAt(0).toUpperCase()}
              </div>
            )}
            <div
              className={`message ${
                msg.isUser ? "user-message" : "other-message"
              }`}
            >
              {!msg.isUser && (
                <div className="message-sender">{msg.authorName}</div>
              )}
              <div className="message-content">{msg.content}</div>
              {(() => {
                try {
                  const date = new Date(msg.timestamp);
                  if (isNaN(date.getTime())) return null; // Return null for invalid dates
                  return (
                    <div className="message-time">
                      {date.toLocaleTimeString("sl-SI", {
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </div>
                  );
                } catch (e) {
                  return null;
                }
              })()}
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      <form onSubmit={handleSendMessage} className="message-form">
        <input
          type="text"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Vnesite sporočilo..."
          autoComplete="off"
          className="message-input"
          disabled={isLoading}
        />
        <button
          type="submit"
          disabled={!message.trim() || isLoading}
          className="send-button"
        >
          <FiSend size={20} />
        </button>
      </form>
    </div>
  );
};

export default ChatPage;
