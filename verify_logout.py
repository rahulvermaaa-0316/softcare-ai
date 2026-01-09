
from app import app
from flask import session

def test_logout():
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user"] = {"email": "test@example.com"}
        
        response = client.get("/logout", follow_redirects=False)
        
        # Check redirect
        assert response.status_code == 302
        assert response.location == "/login-page" or response.location.endswith("/login-page")
        
        # Check session cleared
        with client.session_transaction() as sess:
            assert "user" not in sess
            
        print("✅ Logout test passed!")

if __name__ == "__main__":
    test_logout()
