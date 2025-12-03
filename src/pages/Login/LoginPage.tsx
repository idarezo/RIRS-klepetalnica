import { useState } from "react";
import { useNavigate } from "react-router-dom";
import LoginForm from "../../components/Login/LoginForm";
import { useAuth } from "../../App";
import "../../components/Login/LoginForm.css";
import "./LoginPage.css";

const LoginPage: React.FC = () => {
  const [error, setError] = useState("");
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleLogin = async (username: string, password: string) => {
    try {
      console.log("Attempting login with:", username);
      const response = await fetch("http://localhost:3000/userLogin", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          emailValue: username,
          psw: password,
        }),
      });

      // Try to parse as JSON, fallback to text if it fails
      let data;
      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        data = await response.json();
      } else {
        const text = await response.text();
        data = { message: text };
      }

      console.log("Login response:", data);

      if (!response.ok) {
        throw new Error(data.message || "Prijava ni uspela");
      }

      // Store user data and token
      const userData = {
        email: data.user?.email,
        token: data.token,
        ...data.user,
      };

      localStorage.setItem("user", JSON.stringify(userData));
      console.log("User data stored, redirecting...");

      login(data.token, data.user?.username || data.user?.email || "User");

      navigate("/welcome", { replace: true });
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Napačno uporabniško ime ali geslo"
      );
    }
  };

  return (
    <div className="login-container">
      <div className="auth-container">
        <h2>Prijava</h2>
        {error && <div className="error-message">{error}</div>}
        <LoginForm onSubmit={handleLogin} error={error} />
        <div className="auth-links">
          <p>
            Nimaš računa? <a href="/register">Registriraj se</a>
          </p>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
