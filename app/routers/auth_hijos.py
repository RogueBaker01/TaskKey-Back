from fastapi import APIRouter, Depends, HTTPException, status
from app.database import get_db
from app.schemas.children import ChildLogin, ChildResponse
from app.utils.security import verificar_codigo_hijo, create_access_token
from app.utils.dependencies import get_current_child

# Rutas de autenticacion de hijos
router = APIRouter(prefix="/api/auth_hijos", tags=["Autenticación Hijos"])


@router.post("/auth_codigo")
def auth_codigo_hijo(data: ChildLogin, conn=Depends(get_db)):

    # Verificar el código contra los hashes vigentes en la BD
    child_id = verificar_codigo_hijo(conn, data.codigo)

    if not child_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Código inválido o expirado",
        )

    # Obtener el perfil completo del niño
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, parent_id, nombre, apellido, fecha_nacimiento, created_at FROM children WHERE id = %s",
        (str(child_id),),
    )
    child = cursor.fetchone()
    cursor.close()

    if not child:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Perfil del niño no encontrado",
        )

    # Generar token JWT para la sesión del niño
    token = create_access_token(
        data={"sub": str(child["id"]), "role": "child"}
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "child": {
            "id": str(child["id"]),
            "nombre": child["nombre"],
            "apellido": child["apellido"],
            "fecha_nacimiento": str(child["fecha_nacimiento"]) if child["fecha_nacimiento"] else None,
        },
    }

#Ruta para obtener el perfil del hijo autenticado
@router.get("/me_hijo", response_model=ChildResponse)
def get_me_hijo(conn=Depends(get_db), current_user: dict = Depends(get_current_child)):
    cursor = conn.cursor()
    
    # Busca el usuario por id
    cursor.execute(
        "SELECT id, parent_id, nombre, apellido, fecha_nacimiento, created_at FROM children WHERE id = %s",
        (current_user["id"],),
    )
    user = cursor.fetchone()
    cursor.close()
    #Verifica que el usuario exista
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Perfil del niño no encontrado",
        )
    return {
        "id": str(user["id"]),
        "parent_id": str(user["parent_id"]),
        "nombre": user["nombre"],
        "apellido": user["apellido"],
        "fecha_nacimiento": str(user["fecha_nacimiento"]) if user["fecha_nacimiento"] else None,
    }
