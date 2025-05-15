from fastapi import FastAPI, Response, status, HTTPException, Depends, APIRouter
from sqlalchemy.ext.asyncio import AsyncSession 
from app.db.database import get_session
from app.v1.schemas.auth import UserOut
from app.utils.utils import generate_password_hash,verify_password,create_access_token,decode_access_token
from app.v1.models import models
from app.v1.service.auth import AuthService
from app.v1.schemas.auth import UserCreate,UserPostModel, EmailModel, UpdatePassword, PasswordRequestModel,PasswordResetConfirmModel
from fastapi.responses import JSONResponse
from app.core.depedencies import RefreshTokenBearer,AccessTokenBearer, get_current_user,RoleChecker
from datetime import datetime
from app.utils.utils import create_access_token, create_url_safe_token, decode_url_safe_token
from app.utils.redis import add_jti_to_blocklist
from app.utils.errors import UserAlreadyExists,InvalidCredentials,InvalidToken, UserNotFound
from app.utils.mail import mail, create_message
from app.utils.config import settings
from fastapi import BackgroundTasks
from app.db.celery_task import send_mail


auth_router = APIRouter()

auth_service = AuthService()

role_checker = RoleChecker(["admin","user"])


@auth_router.post("/send_email")
async def send_email(email:EmailModel):
    emails = email.addresses
    
    html = "<h1>Welcome to the Best EBA</h1>"
    subject = "We are glad to have you at eba and sons"
    
    # Using celery tasks
    send_mail.delay(emails,subject,html)     
        
    # message = create_message(recipients=emails,subject=subject,body=html)
    
    # await mail.send_message(message)
    
    return {"message":"The mail was sent succesfully"}




@auth_router.post("/signup", status_code=status.HTTP_201_CREATED)
async def create_user(bg_task: BackgroundTasks,user_data: UserCreate, session: AsyncSession = Depends(get_session)):
    
    
    emails = user_data.email
        
    user_exists = await auth_service.user_exists(emails,session)
        
    if user_exists:
        raise UserAlreadyExists()

  
    new_user = await auth_service.create_user(user_data,session)
                
    # Add email logic to verify user account
    token = create_url_safe_token({"email":emails})
                
    link = f"http://{settings.DOMAIN}/api/v1/auth/verify/{token}"
                
    html_message = f"""
    <h2>Verify your Email</h2>
    <p>Please click this <a href="{link}">link</a> to verify your email address</p>
    """
    subject= "Verify your email"
    
    # Using celery Tasks
    send_mail.delay([emails],subject,html_message)
                
    # message = create_message(recipients=[emails], subject=subject, body=html_message)
    
    # bg_task.add_task(mail.send_message,message)
    
    return {
        "message":"Account created, Please check your inbox to verify your email",
        "user":new_user
    }

 
#Users Account Verification link
@auth_router.get("/verify/{token}")
async def verify_user_email(token:str,session:AsyncSession=Depends(get_session)):
    token_data = decode_url_safe_token(token=token)
    user_email = token_data.get("email")
    
    if user_email:
        user = await auth_service.get_user_by_email(user_email,session)
        
        if not user:
            raise UserNotFound()
        
        await auth_service.update_user(user,{"is_verified":True}, session)
        
        return JSONResponse(
            content={"message":"Account Verified Successfully"},
            status_code=status.HTTP_200_OK
        )
    return JSONResponse(
        content={"message":"Error occured while verifiying email"},
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
    )    
    
# Password rest on account
@auth_router.post("/password_reset")
async def reset_password(user_data: UpdatePassword, session:AsyncSession=Depends(get_session)):
    user_email = user_data.email
    user_password = user_data.password
    new_password_update = user_data.new_password
    
    user = await auth_service.get_user_by_email(user_email,session)
    
    if user is not None:
        password_valid = verify_password(user_password, user.password_hash)
        
        if password_valid:
            new_password = generate_password_hash(new_password_update)
            
            await auth_service.update_password(user,new_password,session)
            
            return JSONResponse(
                content={"message":"Password reset successful"},
                status_code=status.HTTP_200_OK
            )
    
        return JSONResponse(
            content={"message":"Please check that the password you supplied is valid"},
            status_code=status.HTTP_403_FORBIDDEN
        ) 
        
    return JSONResponse(
        content={"message":"User isn't on this system"},
        status_code=status.HTTP_404_NOT_FOUND
    )
        
    
    
# Password reset with token
@auth_router.post("/password-reset-request")
async def password_reset_request(email_data:PasswordRequestModel):
    emails = email_data.email
    
    token = create_url_safe_token({"email":emails})
    
    link = f"http://{settings.DOMAIN}/api/v1/auth/password-reset-confirm/{token}"
    
    html_message = f"""
    <h2>Reset Your Password</h2>
    <p>Please click this <a href="{link}">link</a> to Reset your Password</p>
    """
    
    subject ="Reset your password"
    
    # Using celery tasks
    send_mail.delay([emails], subject,html_message)
        
    return JSONResponse(
        content={"message":"Please check your email for instructions to reset your password"},
        status_code=status.HTTP_200_OK
    )
    
    
@auth_router.post("/password-reset-confirm/{token}")
async def reset_account_password(token:str,passwords:PasswordResetConfirmModel, session:AsyncSession=Depends(get_session)):
    new_password = passwords.new_password
    confirm_password = passwords.confirm_new_password
    
    if new_password != confirm_password:
        raise HTTPException(detail="Passwords do not match", status_code=status.HTTP_400_BAD_REQUEST)
    
    token_data = decode_url_safe_token(token)
    
    user_email = token_data.get("email")
    
    if user_email:
        user = await auth_service.get_user_by_email(user_email,session)
        
        if not user:
            raise UserNotFound()
        
        passwd_hash = generate_password_hash(new_password)
        await auth_service.update_password(user,passwd_hash,session)
        
        return JSONResponse(
            content={"message":"Password reset successfully"},
            status_code=status.HTTP_200_OK
        )
    
    return JSONResponse(
        content={"message":"Error occured during password reset"},
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
    )
    
    
    
@auth_router.post("/login")
async def login_user(user_data:UserCreate, session: AsyncSession=Depends(get_session)):
    
    user_email = user_data.email
    user_password = user_data.password

    user = await auth_service.get_user_by_email(user_email,session)
    
    if user is not None:
        password_valid = verify_password(user_password, user.password_hash)
        
        if password_valid:
            access_token = create_access_token(user_data={"email":user.email, "user_uid":str(user.uid)})
            refresh_token = create_access_token(user_data={"email":user.email,"user_uid":str(user.uid)}, refresh=True)
            
            return JSONResponse(
                content={
                    "message":"Login successful",
                    "access_token":access_token,
                    "refresh_token":refresh_token,
                    "user": {"email": user.email,"user_uid":str(user.uid)}
                }
            )

    raise InvalidCredentials()
    # sent

@auth_router.get("/refresh_token")
async def generate_new_access_token(token_details:dict=RefreshTokenBearer()):
    
    expiry_time = token_details["exp"]
    
    if datetime.fromtimestamp(expiry_time) > datetime.now():
        access_token = create_access_token(user_data=token_details["user"])
        
        return JSONResponse(content={"access_token": access_token})
    
    raise InvalidToken()

@auth_router.get("/me", response_model=UserPostModel)
async def get_current_user(user =Depends(get_current_user), _:bool =Depends(role_checker)):
    return user

@auth_router.get("/logout")
async def revoke_token(token_details: dict=Depends(AccessTokenBearer())):

    jti=token_details["jti"]
    
    await add_jti_to_blocklist(jti=jti)
    
    return JSONResponse(content={
        "message":"Logged Out Successfully"
    },
    status_code=status.HTTP_200_OK
                        
    )
    



