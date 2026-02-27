from fastapi import APIRouter, Depends, HTTPException, status
from app.database import get_db
from app.schemas.children import ChildLogin
from app.utils.security import verificar_codigo_hijo, create_access_token

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