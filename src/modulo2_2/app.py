from __future__ import annotations

import os
from collections.abc import Generator
from datetime import datetime
from datetime import timedelta
from datetime import timezone

from fastapi import Depends
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import status
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from jose import JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from sqlalchemy import create_engine
from sqlalchemy import ForeignKey
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker

SECRET_KEY = os.getenv("SECRET_KEY", "modulo2-2-dev-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    orders: Mapped[list[Order]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )


class Order(Base):
    __tablename__ = "orders"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    user: Mapped[User] = relationship(back_populates="orders")
    items: Mapped[list[OrderItem]] = relationship(
        back_populates="order",
        cascade="all, delete-orphan",
    )


class OrderItem(Base):
    __tablename__ = "order_items"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    order_id: Mapped[int] = mapped_column(ForeignKey("orders.id"), index=True)
    product_name: Mapped[str] = mapped_column(String(100))
    quantity: Mapped[int] = mapped_column(default=1)
    unit_price: Mapped[float] = mapped_column(default=0.0)
    order: Mapped[Order] = relationship(back_populates="items")


class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class UserUpdate(BaseModel):
    username: str | None = None
    email: str | None = None
    password: str | None = None


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str


class UserAuth(BaseModel):
    username: str
    password: str


class OrderCreate(BaseModel):
    user_id: int
    status: str = "pending"


class OrderUpdate(BaseModel):
    user_id: int | None = None
    status: str | None = None


class OrderRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    status: str


class OrderItemCreate(BaseModel):
    order_id: int
    product_name: str
    quantity: int = 1
    unit_price: float = 0.0


class OrderItemUpdate(BaseModel):
    order_id: int | None = None
    product_name: str | None = None
    quantity: int | None = None
    unit_price: float | None = None


class OrderItemRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    order_id: int
    product_name: str
    quantity: int
    unit_price: float


class OrderDetail(OrderRead):
    items: list[OrderItemRead] = Field(default_factory=list)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
    )
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    print("plain_password:", plain_password)
    print("hashed_password:", hashed_password)
    result = pwd_context.verify(plain_password, hashed_password)
    print("pwd_context.verify:", result)
    return result


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def get_db_session(database_url: str) -> tuple[Session, sessionmaker]:
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False}
        if database_url.startswith("sqlite")
        else {},
        future=True,
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    return SessionLocal, SessionLocal


def create_app(database_url: str | None = None) -> FastAPI:
    database_url = database_url or os.getenv(
        "DATABASE_URL",
        "sqlite:///./modulo2_2.db",
    )
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False}
        if database_url.startswith("sqlite")
        else {},
        future=True,
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def get_db() -> Generator[Session]:
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app = FastAPI(title="Modulo2_2 API")

    def require_user(
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db),
    ) -> User:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str | None = payload.get("sub")
            if username is None:
                raise credentials_exception
        except JWTError as exc:
            raise credentials_exception from exc

        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise credentials_exception
        return user

    @app.post("/auth/login", response_model=Token)
    def login(
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_db),
    ) -> Token:
        user = (
            db.query(User)
            .filter(
                User.username == form_data.username,
            )
            .first()
        )
        if not user or not verify_password(
            form_data.password,
            user.hashed_password,
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
            )
        token = create_access_token(user.username)
        return Token(access_token=token)

    @app.post(
        "/users/",
        response_model=UserRead,
        status_code=status.HTTP_201_CREATED,
    )
    def create_user(
        payload: UserCreate,
        db: Session = Depends(get_db),
    ) -> User:
        if (
            db.query(User)
            .filter(
                (User.username == payload.username) | (User.email == payload.email),
            )
            .first()
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already in use",
            )

        user = User(
            username=payload.username,
            email=payload.email,
            hashed_password=get_password_hash(payload.password),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    @app.get("/users/", response_model=list[UserRead])
    def list_users(
        db: Session = Depends(get_db),
        current_user: User = Depends(require_user),
    ) -> list[User]:
        return db.query(User).all()

    @app.get("/users/{user_id}", response_model=UserRead)
    def get_user(
        user_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_user),
    ) -> User:
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        return user

    @app.put("/users/{user_id}", response_model=UserRead)
    def update_user(
        user_id: int,
        payload: UserUpdate,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_user),
    ) -> User:
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        if payload.username is not None:
            user.username = payload.username
        if payload.email is not None:
            user.email = payload.email
        if payload.password is not None:
            user.hashed_password = get_password_hash(payload.password)
        db.commit()
        db.refresh(user)
        return user

    @app.delete("/users/{user_id}", response_model=UserRead)
    def delete_user(
        user_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_user),
    ) -> User:
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        db.delete(user)
        db.commit()
        return user

    @app.post(
        "/orders/",
        response_model=OrderRead,
        status_code=status.HTTP_201_CREATED,
    )
    def create_order(
        payload: OrderCreate,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_user),
    ) -> Order:
        if db.query(User).filter(User.id == payload.user_id).first() is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        order = Order(user_id=payload.user_id, status=payload.status)
        db.add(order)
        db.commit()
        db.refresh(order)
        return order

    @app.get("/orders/", response_model=list[OrderRead])
    def list_orders(
        db: Session = Depends(get_db),
        current_user: User = Depends(require_user),
    ) -> list[Order]:
        return db.query(Order).all()

    @app.get("/orders/{order_id}", response_model=OrderDetail)
    def get_order(
        order_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_user),
    ) -> Order:
        order = db.query(Order).filter(Order.id == order_id).first()
        if order is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Order not found",
            )
        return order

    @app.put("/orders/{order_id}", response_model=OrderRead)
    def update_order(
        order_id: int,
        payload: OrderUpdate,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_user),
    ) -> Order:
        order = db.query(Order).filter(Order.id == order_id).first()
        if order is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Order not found",
            )
        if payload.user_id is not None:
            if (
                db.query(User)
                .filter(
                    User.id == payload.user_id,
                )
                .first()
                is None
            ):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found",
                )
            order.user_id = payload.user_id
        if payload.status is not None:
            order.status = payload.status
        db.commit()
        db.refresh(order)
        return order

    @app.delete("/orders/{order_id}", response_model=OrderRead)
    def delete_order(
        order_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_user),
    ) -> Order:
        order = db.query(Order).filter(Order.id == order_id).first()
        if order is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Order not found",
            )
        db.delete(order)
        db.commit()
        return order

    @app.post(
        "/order-items/",
        response_model=OrderItemRead,
        status_code=status.HTTP_201_CREATED,
    )
    def create_order_item(
        payload: OrderItemCreate,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_user),
    ) -> OrderItem:
        if (
            db.query(Order)
            .filter(
                Order.id == payload.order_id,
            )
            .first()
            is None
        ):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Order not found",
            )

        item = OrderItem(
            order_id=payload.order_id,
            product_name=payload.product_name,
            quantity=payload.quantity,
            unit_price=payload.unit_price,
        )
        db.add(item)
        db.commit()
        db.refresh(item)
        return item

    @app.get("/order-items/", response_model=list[OrderItemRead])
    def list_order_items(
        db: Session = Depends(get_db),
        current_user: User = Depends(require_user),
    ) -> list[OrderItem]:
        return db.query(OrderItem).all()

    @app.get("/order-items/{item_id}", response_model=OrderItemRead)
    def get_order_item(
        item_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_user),
    ) -> OrderItem:
        item = db.query(OrderItem).filter(OrderItem.id == item_id).first()
        if item is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Order item not found",
            )
        return item

    @app.put("/order-items/{item_id}", response_model=OrderItemRead)
    def update_order_item(
        item_id: int,
        payload: OrderItemUpdate,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_user),
    ) -> OrderItem:
        item = (
            db.query(OrderItem)
            .filter(
                OrderItem.id == item_id,
            )
            .first()
        )
        if item is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Order item not found",
            )
        if payload.order_id is not None:
            if db.query(Order).filter(Order.id == payload.order_id).first() is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Order not found",
                )
            item.order_id = payload.order_id
        if payload.product_name is not None:
            item.product_name = payload.product_name
        if payload.quantity is not None:
            item.quantity = payload.quantity
        if payload.unit_price is not None:
            item.unit_price = payload.unit_price
        db.commit()
        db.refresh(item)
        return item

    @app.delete("/order-items/{item_id}", response_model=OrderItemRead)
    def delete_order_item(
        item_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_user),
    ) -> OrderItem:
        item = db.query(OrderItem).filter(OrderItem.id == item_id).first()
        if item is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Order item not found",
            )
        db.delete(item)
        db.commit()
        return item

    return app


app = create_app()
