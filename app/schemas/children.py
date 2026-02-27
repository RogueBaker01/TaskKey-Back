from pydantic import BaseModel

# Schema para login del hijo con codigo
class ChildLogin(BaseModel):
    codigo: str
