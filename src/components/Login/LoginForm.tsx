import { useState } from "react";

interface LoginFormProps {
  onSubmit: (username: string, password: string) => void;
  error?: string;
}

const LoginForm: React.FC<LoginFormProps> = ({ onSubmit, error }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    e.stopPropagation();
    onSubmit(username, password);
  };

  return (
    <form onSubmit={handleSubmit} className="login-form">
      {error && <div className="form-error">{error}</div>}
      <div className="form-group">
        <label htmlFor="username">Uporabniško ime</label>
        <input
          type="text"
          id="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Vnesite uporabniško ime"
          required
        />
      </div>
      <div className="form-group">
        <label htmlFor="password">Geslo</label>
        <input
          type="password"
          id="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Vnesite geslo"
          required
        />
      </div>
      <button type="submit" className="login-btn">
        Prijavi se
      </button>
    </form>
  );
};

export default LoginForm;
