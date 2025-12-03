import { useState, useEffect } from "react";
import "./RegisterForm.css";

export interface RegisterFormData {
  username: string;
  email: string;
  password: string;
  lastName: string;
}

interface RegisterFormProps {
  onSubmit: (formData: RegisterFormData) => void;
  error?: string;
}

const RegisterForm: React.FC<RegisterFormProps> = ({ onSubmit, error }) => {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [lastName, setLastName] = useState("");
  const [localError, setLocalError] = useState<string | undefined>(undefined);

  useEffect(() => {
    if (error) {
      setLocalError(error);

      const timer = setTimeout(() => {
        setLocalError(undefined);
      }, 3000);

      return () => clearTimeout(timer);
    }
  }, [error]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      alert("Gesli se ne ujemata!");
      return;
    }
    onSubmit({ username, email, password, lastName });
  };

  return (
    <div className="auth-form">
      <h2>Registracija</h2>
      {localError && <div className="error-message">{localError}</div>}
      <form onSubmit={handleSubmit} className="register-form">
        <div className="form-grid">
          <div className="form-group">
            <label htmlFor="username">Uporabniško ime</label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="lastName">Priimek</label>
            <input
              type="text"
              id="lastName"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="email">E-pošta</label>
            <input
              type="email"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div className="form-group password-group">
            <label htmlFor="password">Geslo</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="password-input"
            />
          </div>
          <div className="form-group confirm-password-group">
            <label htmlFor="confirmPassword">Potrdi geslo</label>
            <input
              type="password"
              id="confirmPassword"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              className="confirm-password-input"
            />
          </div>
        </div>
        <button type="submit" className="auth-button">
          Registriraj se
        </button>
      </form>
    </div>
  );
};

export default RegisterForm;
