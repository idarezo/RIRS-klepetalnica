import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../App";
import "./Welcome.css";

const Welcome: React.FC = () => {
  const [username, setUsername] = useState<string>("Uporabnik");
  const navigate = useNavigate();
  const { logout } = useAuth();

  useEffect(() => {
    // Get user data from localStorage
    const userData = localStorage.getItem("user");
    if (userData) {
      try {
        const user = JSON.parse(userData);
        setUsername(user.username || user.email || "Uporabnik");
      } catch (e) {
        console.error("Error parsing user data:", e);
      }
    }
  }, []);

  const handleLogout = () => {
    logout();
    navigate("/login", { replace: true });
  };

  return (
    <div className="welcome-container">
      <div className="welcome-box">
        <h1>Dobrodošli, {username}!</h1>
        <p>Uspešno ste se prijavili v aplikacijo.</p>
        <div className="welcome-actions">
          <button onClick={() => navigate("/chat")} className="btn primary">
            Pojdi na klepet
          </button>
          <button onClick={handleLogout} className="btn secondary">
            Odjava
          </button>
        </div>
      </div>
    </div>
  );
};

export default Welcome;
