from fastapi import APIRouter, Depends, HTTPException, status
from app.database import get_db
from app.schemas.user import UserRegister, UserLogin, UserResponse, TokenResponse
from app.utils.security import hash_password, verify_password, create_access_token
from app.utils.dependencies import get_current_user

#Rutas de autenticacion
router = APIRouter(prefix="/api/auth", tags=["Autenticación"])

#Ruta de registro
@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserRegister, conn=Depends(get_db)):
    
    #Cursor para la base de datos
    cursor = conn.cursor()

    # Verifica si el email ya existe
    cursor.execute("SELECT id FROM users WHERE email = %s", (user_data.email,))
    if cursor.fetchone():
        cursor.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El correo ya está registrado",
        )

    # Verifica si el username ya existe
    cursor.execute("SELECT id FROM users WHERE username = %s", (user_data.username,))
    if cursor.fetchone():
        cursor.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El nombre de usuario ya está en uso",
        )

    # Hashea la contraseña e inserta
    hashed = hash_password(user_data.password)
    cursor.execute(
        """
        INSERT INTO users (username, email, password_hash)
        VALUES (%s, %s, %s)
        RETURNING id, username, email, created_at
        """,
        (user_data.username, user_data.email, hashed),
    )
    new_user = cursor.fetchone()
    conn.commit()
    cursor.close()

    # Crea el token JWT
    token = create_access_token(
        data={"sub": str(new_user["id"]), "email": new_user["email"]}
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": new_user,
    }

#Ruta de login del usuario 
@router.post("/login", response_model=TokenResponse)
def login(user_data: UserLogin, conn=Depends(get_db)):
    
    cursor = conn.cursor()

    # Busca el usuario por email
    cursor.execute(
        "SELECT id, username, email, password_hash, created_at FROM users WHERE email = %s",
        (user_data.email,),
    )
    user = cursor.fetchone()
    cursor.close()

    # Verifica que el usuario exista
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Correo o contraseña incorrectos",
        )

    # Verifica la contraseña
    if not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Correo o contraseña incorrectos",
        )

    # Crea el token JWT
    token = create_access_token(
        data={"sub": str(user["id"]), "email": user["email"]}
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "created_at": user["created_at"],
        },
    }

#Ruta para obtener el perfil del usuario autenticado
@router.get("/me", response_model=UserResponse)
def get_me(conn=Depends(get_db), current_user: dict = Depends(get_current_user)):
    
    cursor = conn.cursor()
    
    # Busca el usuario por id
    cursor.execute(
        "SELECT id, username, email, created_at FROM users WHERE id = %s",
        (current_user["id"],),
    )
    user = cursor.fetchone()
    cursor.close()

    # Verifica que el usuario exista
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado",
        )

    return user
