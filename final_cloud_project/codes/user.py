import socket
import json
import pyotp

### Step 7: Time-Based OTP Authentication ###
def generate_totp_secret():
    return pyotp.random_base32()

def get_time_based_otp(secret):
    return pyotp.TOTP(secret).now()

def verify_time_based_otp(secret, token):
    return pyotp.TOTP(secret).verify(token)

def user_server(query):
    user_id = "user123"
    user_totp_secret = generate_totp_secret()
    user_token = get_time_based_otp(user_totp_secret)
    print(user_totp_secret)
    print(f"🔑 Use this OTP for authentication: {user_token}")

    message={"data": query,"user_token":user_token,"user_totp_secret":user_totp_secret}


    #sending query to public server
    public_cloud_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    public_cloud_socket.connect(("localhost", 6000))  # Public Cloud Server
    public_cloud_socket.send(json.dumps(message).encode())

    #reciving documents from private server
    user_server_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    user_server_socket.bind(("localhost",5000))
    user_server_socket.listen(5)
    print("User server started....")

    while True:
        private_server_conn,private_server_addr=user_server_socket.accept()
        data=json.loads(private_server_conn.recv(4096).decode())
        print(data)

if __name__ == "__main__":
    query = input("Enter your search query: ")
    user_server(query)