import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../App";

const ProfilePage: React.FC = () => {
  const [userData, setUserData] = useState({
    username: "uporabnik123",
    email: "uporabnik@example.com",
    fullName: "Janez Novak",
    bio: "Lahko mi pišete sporočila!",
  });
  const [isEditing, setIsEditing] = useState(false);
  const navigate = useNavigate();
  const { logout } = useAuth();

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
    // TODO: Implement save to backend
    setIsEditing(false);
  };

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="profile-page">
      <div className="profile-header">
        <h1>Moj profil</h1>
        <div className="profile-actions">
          {isEditing ? (
            <>
              <button onClick={handleSave} className="save-button">
                Shrani
              </button>
              <button
                onClick={() => setIsEditing(false)}
                className="cancel-button"
              >
                Prekliči
              </button>
            </>
          ) : (
            <button onClick={() => setIsEditing(true)} className="edit-button">
              Uredi profil
            </button>
          )}
          <button onClick={handleLogout} className="logout-button">
            Odjava
          </button>
        </div>
      </div>

      <div className="profile-content">
        <div className="profile-avatar">
          <div className="avatar-placeholder">
            {userData.username.charAt(0).toUpperCase()}
          </div>
          {isEditing && (
            <button className="change-avatar-button">Spremeni sliko</button>
          )}
        </div>

        <div className="profile-details">
          <div className="form-group">
            <label>Uporabniško ime</label>
            {isEditing ? (
              <input
                type="text"
                name="username"
                value={userData.username}
                onChange={handleInputChange}
                className="form-input"
              />
            ) : (
              <p>{userData.username}</p>
            )}
          </div>

          <div className="form-group">
            <label>E-pošta</label>
            {isEditing ? (
              <input
                type="email"
                name="email"
                value={userData.email}
                onChange={handleInputChange}
                className="form-input"
              />
            ) : (
              <p>{userData.email}</p>
            )}
          </div>

          <div className="form-group">
            <label>Polno ime</label>
            {isEditing ? (
              <input
                type="text"
                name="fullName"
                value={userData.fullName}
                onChange={handleInputChange}
                className="form-input"
              />
            ) : (
              <p>{userData.fullName}</p>
            )}
          </div>

          <div className="form-group">
            <label>O meni</label>
            {isEditing ? (
              <textarea
                name="bio"
                value={userData.bio}
                onChange={handleInputChange}
                className="form-textarea"
                rows={4}
              />
            ) : (
              <p>{userData.bio}</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProfilePage;
