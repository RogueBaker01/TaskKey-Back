from pydantic import BaseModel

# Schema para login del hijo con codigo
class ChildLogin(BaseModel):
    codigo: str

# Schema de respuesta para el perfil del hijo
class ChildResponse(BaseModel):
    id: str
    parent_id: str
    nombre: str
    apellido: str
    fecha_nacimiento: str
