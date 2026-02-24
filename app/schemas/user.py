from pydantic import BaseModel
from uuid import UUID
from datetime import datetime

#Esquemas para validar datos de entrada y de salida del usuario

#Esquema de registro
class UserRegister(BaseModel):

    username: str
    email: str
    password: str

#Esquema de login
class UserLogin(BaseModel):
    email: str
    password: str


#Esquema de respuesta
class UserResponse(BaseModel):
    id: UUID
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True

#Esquema de respuesta del token

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
