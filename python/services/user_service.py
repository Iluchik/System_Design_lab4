from fastapi import HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from model.model import User_description, User, get_db

SECRET_KEY = "System-design-Lab2"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MIN = 20

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ==== User service ===================================================================================================

# Черный список токенов доступа
token_BL = []

class user_service():

	async def authentification(self, token: str = Depends(oauth2_scheme), db:Session = Depends(get_db)):
		credentials_exception = HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Invalid credentials",
			headers={"WWW-Authenticate": "Bearer"}
		)
		try:
			if token in token_BL:
				raise credentials_exception
			payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
			email: str = payload.get("sub")
			user = db.query(User).filter(User.email == email).first()
			if user is None:
				raise credentials_exception
			return {"user": user, "token": token}
		except JWTError:
			raise credentials_exception

	def authorization(self, data: dict, expires_delta: Optional[timedelta] = None):
		payload = data.copy()
		if expires_delta:
			expire = datetime.utcnow() + expires_delta
		else:
			expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MIN)
		payload.update({"exp": expire})
		token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
		return token

	async def create_user(self, user: User_description, db: Session):
		user.password = pwd_context.hash(user.password)
		db_user = User(**user.dict())
		db.add(db_user)
		db.commit()
		db.refresh(db_user)
		return db_user

	async def login(self, form_data: OAuth2PasswordRequestForm, email: str, db: Session):
		user = db.query(User).filter(User.email == email).first()
		if user is None:
			raise HTTPException(
				status_code=status.HTTP_401_UNAUTHORIZED,
				detail="Incorrect email, username or password",
				headers={"WWW-Authenticate": "Bearer"}
			)
		if pwd_context.verify(form_data.password, user.password):
			expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MIN)
			access_token = self.authorization(data={"sub": email}, expires_delta=expire)
			return {"access_token": access_token, "token_type": "bearer"}
		else:
			raise HTTPException(
				status_code=status.HTTP_401_UNAUTHORIZED,
				detail="Incorrect email, username or password",
				headers={"WWW-Authenticate": "Bearer"}
			)

	async def get_users(self, db: Session):
		return db.query(User).all()

	async def get_user(self, user_id: int, db: Session):
		user = db.query(User).filter(User.id == user_id).first()
		if user is None:
			raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
		return user

	async def update_user(self, updated_user: User_description, current_user: dict, db: Session):
		user = db.query(User).filter(User.id == current_user["user"].id).first()
		if user is None:
			raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
		user.first_name = updated_user.first_name
		user.last_name = updated_user.last_name
		user.email = updated_user.email
		user.password = pwd_context.hash(updated_user.password)
		user.age = updated_user.age
		user.adress = updated_user.adress
		user.phone = updated_user.phone
		db.commit()
		return user

	async def delete_account(self, current_user: dict, db: Session):
		user = db.query(User).filter(User.id == current_user["user"].id).first()
		if user is None:
			raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
		db.delete(user)
		db.commit()
		return user

	async def logout(self, current_user: dict, db: Session):
		user = db.query(User).filter(User.id == current_user["user"].id).first()
		if user is None:
			raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
		token_BL.append(current_user["token"])
		return user

# =====================================================================================================================