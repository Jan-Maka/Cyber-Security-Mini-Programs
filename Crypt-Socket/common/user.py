import hashlib
import bcrypt
import base64


class User:
    def __init__(self, username, password,public_key, connection=None):
        self.username = username
        self.user_id = self.hash_username(username)
        if isinstance(password, bytes):
            self.password = password
        else:
            self.password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        self.public_key = public_key
        self.session_key = None
        self.connection = connection
        self.message_queue = []
        self.certificate = None

    @staticmethod
    def hash_username(username):
        return hashlib.sha256(username.encode()).hexdigest()
    
    def verify_password(self, password):
        return bcrypt.checkpw(password.encode(), self.password)


    def to_dict(self):
        return {
            "username":self.username,
            "user_id": self.user_id,
            "password": base64.b64encode(self.password).decode('utf-8'),
            "public_key":self.public_key,
            "certificate":self.certificate,
            "session_key":self.session_key,
            "message_queue":self.message_queue
        }
    
    @classmethod
    def from_dict(cls, data):
        password_bytes = base64.b64decode(data["password"].encode('utf-8'))
        user = cls(data["username"], '', data["public_key"])
        user.password = password_bytes
        user.user_id = data.get("user_id") or hashlib.sha256(data["username"].encode()).hexdigest()
        user.certificate = data.get("certificate")
        user.message_queue = data.get("message_queue", [])
        user.session_key = data.get("session_key", None)
        return user


    def is_online(self):
        return self.connection is not None