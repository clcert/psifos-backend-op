import redis.asyncio as redis
import json

from cryptography.fernet import Fernet
from uuid import uuid4

from app.config import ENCRYPTION_KEY

# Configuración de Redis
redis_client = redis.Redis(host='redis', port=6379, db=0)
# Configuración de cifrado
cipher_suite = Fernet(ENCRYPTION_KEY)

def generate_session_id():
    """Genera un ID de sesión único."""
    return str(uuid4())

async def store_session_data(session_id: str, data: dict, expires_in: int = 3600):
    """Almacena datos de sesión en Redis con cifrado."""
    serialized_data = json.dumps(data)
    encrypted_data = cipher_suite.encrypt(serialized_data.encode())
    await redis_client.setex(f"session:{session_id}", expires_in, encrypted_data)

async def get_session_data(session_id: str):
    """Recupera y descifra datos de sesión desde Redis."""
    encrypted_data = await redis_client.get(f"session:{session_id}")
    if encrypted_data:
        decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
        return json.loads(decrypted_data)
    return None

async def delete_session_data(session_id: str):
    """Elimina datos de sesión de Redis."""
    await redis_client.delete(f"session:{session_id}")
