
import requests
import json

BASE_URL = "http://127.0.0.1:5000"

def test_signup_existing_user():
    # Only run this if the server is running. 
    # Since I cannot guarantee the server is running in the background for this script to hit separate process,
    # I will use app.test_client() which is more reliable for agent testing without external server.
    
    from app import app, db, User
    
    with app.app_context():
        # Ensure a user exists
        email = "duplicate@test.com"
        user = User.query.filter_by(email=email).first()
        if not user:
            print(f"Creating duplicate user {email}...")
            user = User(name="Duplicate", email=email, password="password", provider="email")
            db.session.add(user)
            db.session.commit()
            print("User created.")
        else:
            print(f"User {email} already exists.")

    # Now test the endpoint using test_client
    with app.test_client() as client:
        print(f"Testing signup with existing email: {email}")
        response = client.post("/signup", 
                             data=json.dumps({
                                 "name": "New Name",
                                 "email": email,
                                 "password": "newpassword"
                             }),
                             content_type='application/json')
        
        print(f"Status Code: {response.status_code}")
        print(f"Content Type: {response.content_type}")
        print(f"Data: {response.data.decode('utf-8')}")
        
        if response.status_code == 400 and response.is_json:
            json_data = response.get_json()
            if json_data.get("error") == "Email already exists":
                print("SUCCESS: Correctly returned JSON error for existing user.")
            else:
                print(f"FAILURE: Unexpected JSON error message: {json_data}")
        else:
            print("FAILURE: Did not return 400 JSON.")

if __name__ == "__main__":
    test_signup_existing_user()
