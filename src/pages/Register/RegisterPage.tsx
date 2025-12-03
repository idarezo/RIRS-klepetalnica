import { useState } from "react";
import { useNavigate } from "react-router-dom";
import RegisterForm from "../../components/Register/RegisterForm";
import type { RegisterFormData } from "../../components/Register/RegisterForm";

const RegisterPage: React.FC = () => {
  const [error, setError] = useState("");
  const navigate = useNavigate();
  const handleRegister = async (formData: RegisterFormData) => {
    const { username, email, password, lastName } = formData;
    try {
      const response = await fetch("http://localhost:3000/userRegistracija", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          firstName: username.trim(),
          lastName: lastName.trim() || "User",
          emailValue: email,
          psw: password,
          rojstniDan: "",
          genderValue: "",
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

      if (!response.ok) {
        if (response.status === 409) {
          throw new Error("Email already in use.");
        }
        throw new Error(data.message || "Prišlo je do napake pri registraciji");
      }

      // Registration successful
      navigate("/login");
    } catch (err) {
      console.error("Registration error:", err);
      setError(
        err instanceof Error ? err.message : "Prišlo je do nepričakovane napake"
      );
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-container">
        <RegisterForm onSubmit={handleRegister} error={error} />
        <div className="auth-links">
          <p>
            Že imaš račun? <a href="/login">Prijavi se</a>
          </p>
        </div>
      </div>
    </div>
  );
};

export default RegisterPage;
