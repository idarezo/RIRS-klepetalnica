import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../App";
import { FiUser, FiLogOut } from "react-icons/fi";
import "./ProfilePage.css";

const ProfilePage: React.FC = () => {
  const [userData, setUserData] = useState({
    username: "",
    email: "",
    firstName: "",
    lastName: "",
  });

  const [isEditing, setIsEditing] = useState(false);
  const navigate = useNavigate();
  const { logout } = useAuth();

  useEffect(() => {
    const storedUser = localStorage.getItem("user");

    if (storedUser) {
      try {
        const user = JSON.parse(storedUser);
        setUserData({
          username: user.username || "",
          email: user.email || "",
          firstName: user.firstName || "",
          lastName: user.lastName || "",
        });
      } catch (error) {
        console.error("Error parsing user data:", error);
      }
    }
  }, []);

  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = e.target;

    setUserData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSave = () => {
    const storedUser = localStorage.getItem("user");

    if (storedUser) {
      try {
        const user = JSON.parse(storedUser);

        const updatedUser = {
          ...user,
          firstName: userData.firstName,
          lastName: userData.lastName,
        };

        localStorage.setItem("user", JSON.stringify(updatedUser));
        setIsEditing(false);
      } catch (error) {
        console.error("Error saving user data:", error);
      }
    }
  };

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="profile-page-container">
      <div className="profile-page">
        <div className="profile-header"></div>

        <div className="profile-content">
          <div className="profile-avatar">
            <div className="avatar-placeholder">
              {userData.firstName
                ? userData.firstName.charAt(0).toUpperCase()
                : "U"}
            </div>

            {isEditing && (
              <button className="change-avatar-button">Spremeni sliko</button>
            )}
          </div>

          <div className="profile-details">
            <div className="form-group">
              <label>Ime</label>
              {isEditing ? (
                <input
                  type="text"
                  name="firstName"
                  value={userData.firstName}
                  onChange={handleInputChange}
                  className="form-input"
                />
              ) : (
                <p>{userData.firstName}</p>
              )}
            </div>

            <div className="form-group">
              <label>Priimek</label>
              {isEditing ? (
                <input
                  type="text"
                  name="lastName"
                  value={userData.lastName}
                  onChange={handleInputChange}
                  className="form-input"
                />
              ) : (
                <p>{userData.lastName}</p>
              )}
            </div>

            <div className="form-group">
              <label>E-pošta</label>
              <p>{userData.email}</p>
            </div>
          </div>

          <div className="back-to-chat">
            <a
              href="#"
              onClick={(e) => {
                e.preventDefault();
                navigate("/chat");
              }}
            >
              ← Nazaj na chat
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProfilePage;
