**This file consists of the entire unaltered output for reference.**

Okay, I am ready to follow the instructions. Here is the code, existing code review comments, and the relevant parts of the project plan.

**File Structure:**

```
premium-nft-app/
├── backend/          # Python backend code
│   ├── src/        # application sources
│   ├── tests/      # Unit and integration tests
│   ├── Dockerfile  # Containerization definition
│   ├── requirements.txt
│   └── .env.example # Example configuration file
├── frontend/         # React frontend code
│   ├── src/
│   ├── public/
│   ├── Dockerfile
│   ├── package.json
│   └── .env.example
├── docker-compose.yml  # For local development
└── README.md
```

**Codebase with review comments on each file:**

*   ***\***\*backend/requirements.txt\***\***\*

```
fastapi==0.109.2
uvicorn==0.30.1
pydantic==2.6.1
python-jose==3.3.0
passlib==1.7.4
python-multipart==0.0.6
fastapi-mail==1.4.1
requests==2.31.0
python-dotenv==1.0.1
solana==0.28.1
PyYAML==6.0.1
Pillow==10.2.0
SQLAlchemy==2.0.23
psycopg2-binary==2.9.9
```

*(No review comments for this file)*

*   ***\***\*backend/src/.env.example\***\***\*

```
DATABASE_URL=postgresql://user:password@host:port/database
SOLANA_NETWORK="https://api.devnet.solana.com"  # Or mainnet-beta
CRAFT_TOKEN_MINT_ADDRESS="Your CRAFT Token Mint Address"
ADMIN_EMAIL="admin@example.com" #Email address to control administrative actions
EMAIL_USERNAME="your_email@example.com"
EMAIL_PASSWORD="your_email_password"
EMAIL_HOST="smtp.example.com"
EMAIL_PORT=587
SOLANA_PRIVATE_KEY="Your Solana Private Key in Hex Format" #DO NOT COMMIT THIS IN REAL APPS!
```

*Review comment:SOLANA\_PRIVATE\_KEY should not be in the .env file because this is insecure. Key should be handled via a secure vault or KMS in a real deployment.*

*   ***\***\*backend/src/database.py\***\***\*

```python
# backend/src/database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL not set in .env file")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

*(No review comments for this file)*

*   ***\***\*backend/src/models.py\***\***\*

```python
# backend/src/models.py
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

    transactions = relationship("Transaction", back_populates="user")
    nfts = relationship("NFT", back_populates="owner")

class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    nft_id = Column(String)  # Unique NFT identifier
    token_amount = Column(Float)
    transaction_hash = Column(String)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="transactions")

class NFT(Base):
    __tablename__ = "nfts"

    id = Column(Integer, primary_key=True, index=True)
    nft_id = Column(String, unique=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    name = Column(String)
    description = Column(String)
    image_data = Column(String)  # Store the actual SVG/Image data here.  Consider storing a URL instead.
    metadata_url = Column(String)  # Off-chain metadata (if applicable)

    owner = relationship("User", back_populates="nfts")
```

*(No review comments for this file)*

*   ***\***\*backend/src/utils.py\***\***\*

```python
# backend/src/utils.py
import os
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from dotenv import load_dotenv
from passlib.context import CryptContext
import hashlib

load_dotenv()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Email configuration
conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("EMAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("EMAIL_PASSWORD"),
    MAIL_FROM=os.getenv("EMAIL_USERNAME"),
    MAIL_PORT=int(os.getenv("EMAIL_PORT") or 587),  # Provide a default value if not set
    MAIL_SERVER=os.getenv("EMAIL_HOST"),
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
)

async def send_email(subject: str, email_to: str, body: str):
    message = MessageSchema(
        subject=subject,
        recipients=[email_to],
        body=body,
        subtype="html"
    )

    fm = FastMail(conf)
    try:
        await fm.send_message(message)
    except Exception as e:
        print(f"Error sending email: {e}")


def generate_unique_nft_id(user_id: int, timestamp: float):
    """Generates a unique NFT ID based on user ID and timestamp."""
    data = f"{user_id}-{timestamp}".encode('utf-8')
    return hashlib.sha256(data).hexdigest()
```

*(No review comments for this file)*

*   ***\***\*backend/src/solana\_utils.py\***\***\*

```python
# backend/src/solana_utils.py
from solana.rpc.api import Client
from solders.pubkey import Pubkey
from solana.keypair import Keypair
from solana.transaction import Transaction, TransactionInstruction
from solders.system_program import ID as SYSTEM_PROGRAM_ID
from dotenv import load_dotenv
import os
from solders.hash import Hash
from solders.system_program import transfer
import base64

load_dotenv()

SOLANA_NETWORK = os.getenv("SOLANA_NETWORK")
CRAFT_TOKEN_MINT_ADDRESS = os.getenv("CRAFT_TOKEN_MINT_ADDRESS")
SOLANA_PRIVATE_KEY = os.getenv("SOLANA_PRIVATE_KEY")

def get_solana_client():
    return Client(SOLANA_NETWORK)

def get_balance(client: Client, public_key: str):
    """Gets the balance of a Solana account."""
    try:
        pub_key = Pubkey.from_string(public_key)
        balance = client.get_balance(pub_key).value
        return balance
    except Exception as e:
        print(f"Error getting balance: {e}")
        return None

def transfer_tokens(client: Client, sender_private_key: str, recipient_public_key: str, amount: int):
    """Transfers tokens from one Solana account to another."""
    try:
        sender_keypair = Keypair.from_secret_key(bytes.fromhex(sender_private_key))
        recipient_pubkey = Pubkey.from_string(recipient_public_key)

        #Use solders library (more updated)
        transfer_instruction = transfer(
            from_pubkey=sender_keypair.pubkey(),
            to_pubkey=recipient_pubkey,
            lamports=amount
        )

        transaction = Transaction().add(transfer_instruction)
        recent_blockhash = client.get_latest_blockhash().value.blockhash
        transaction.recent_blockhash = recent_blockhash
        transaction.sign(sender_keypair)

        result = client.send_raw_transaction(transaction.serialize()) #Send serialized transaction
        return result

    except Exception as e:
        print(f"Error transferring tokens: {e}")
        return None
```

*(No review comments for this file)*

*   ***\***\*backend/src/nft\_generator.py\***\***\*

```python
# backend/src/nft_generator.py
from PIL import Image, ImageDraw, ImageFont
import io
import base64

def generate_nft_image(text: str):
    """Generates a simple NFT image with the given text."""
    try:
        # Create a new image
        img = Image.new('RGB', (500, 500), color='white')
        d = ImageDraw.Draw(img)

        # Choose a font and size
        font_path = "path/to/your/font.ttf"  # Replace with the actual path to a font file
        try:
            font = ImageFont.truetype(font_path, size=50)
        except IOError:
            # If the font isn't found use a default font. This may not support all characters.
            try:
                font = ImageFont.load_default()
            except Exception as e:
                print("Failed to load default font.")
                return None

        # Calculate the text size
        text_width, text_height = d.textsize(text, font=font)

        # Calculate the position to center the text
        x = (500 - text_width) / 2
        y = (500 - text_height) / 2

        # Add the text to the image
        d.text((x, y), text, fill='black', font=font)

        # Save the image to a BytesIO object
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()

        # Encode the image as a base64 string
        encoded_string = base64.b64encode(img_byte_arr).decode('utf-8')

        return encoded_string
    except Exception as e:
        print(f"Error generating NFT image: {e}")
        return None
```

*(No review comments for this file)*

*   ***\***\*backend/src/main.py\***\***\*

```python
# backend/src/main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from . import models, schemas, utils, solana_utils, nft_generator
from .database import engine, get_db
from datetime import timedelta
from .auth import authenticate_user, create_access_token, get_current_user
from fastapi.middleware.cors import CORSMiddleware
import os
from fastapi_mail import MessageSchema, FastMail
from dotenv import load_dotenv
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from typing import Annotated
from fastapi import Header

load_dotenv()

app = FastAPI()

origins = ["*"]  # allow all origins during development, adjust in production

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

models.Base.metadata.create_all(bind=engine)

# Serve static files (e.g., generated images, if stored locally)
app.mount("/static", StaticFiles(directory="static"), name="static")

ACCESS_TOKEN_EXPIRE_MINUTES = 30

### Authentication Routes
@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=schemas.User)
async def read_users_me(current_user: schemas.User = Depends(get_current_user)):
    return current_user

@app.post("/users", response_model=schemas.User)
async def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = utils.get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

### Solana Related Endpoints
@app.get("/balance/{public_key}")
async def get_balance(public_key: str):
    client = solana_utils.get_solana_client()
    balance = solana_utils.get_balance(client, public_key)
    if balance is None:
        raise HTTPException(status_code=500, detail="Failed to retrieve balance")
    return {"balance": balance}

@app.post("/purchase-nft/")
async def purchase_nft(purchase_request: schemas.PurchaseRequest, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    """
    Simulates an NFT purchase.  Important: Replace with actual Solana TX logic.

    """
    user_id = current_user.id
    token_amount = purchase_request.token_amount
    user_solana_address = purchase_request.user_solana_address

    # Input Validation (important for security)
    if not isinstance(token_amount, (int, float)) or token_amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid token amount.")
    if not isinstance(user_solana_address, str) or len(user_solana_address) != 44: #Basic Solana address validation.
         raise HTTPException(status_code=400, detail="Invalid Solana address.")

    # 1. Check user balance (mock, replace with actual Solana check)
    client = solana_utils.get_solana_client()
    balance = solana_utils.get_balance(client, user_solana_address)
    if balance is None or balance < token_amount:
         raise HTTPException(status_code=400, detail="Insufficient balance")

    # 2. Generate NFT (or fetch if it already exists)
    timestamp = utils.datetime.datetime.now().timestamp()
    nft_id = utils.generate_unique_nft_id(user_id, timestamp)
    existing_nft = db.query(models.NFT).filter(models.NFT.nft_id == nft_id).first()

    if existing_nft:
        nft = existing_nft
    else:
        image_data = nft_generator.generate_nft_image(f"NFT for User {user_id}")
        if not image_data:
            raise HTTPException(status_code=500, detail="NFT generation failed")

        # 3. Create NFT record in database
        nft = models.NFT(owner_id=user_id, nft_id=nft_id, name=f"NFT {nft_id}", description="A Premium NFT", image_data=image_data, metadata_url="")
        db.add(nft)

    # 4. Transfer Tokens (Solana)
    sender_private_key = os.getenv("SOLANA_PRIVATE_KEY")
    if not sender_private_key:
        raise HTTPException(status_code=500, detail="Server configuration error: SOLANA_PRIVATE_KEY not set.")

    try:
        transaction_hash = solana_utils.transfer_tokens(client, sender_private_key, user_solana_address, int(token_amount)) #Amount needs to be integer
        if not transaction_hash:
            raise HTTPException(status_code=500, detail="Token transfer failed.")
    except Exception as e:
         print(f"Solana transfer error: {e}")
         raise HTTPException(status_code=500, detail=f"Token transfer failed: {e}")

    # 5. Create Transaction record
    transaction = models.Transaction(user_id=user_id, nft_id=nft.nft_id, token_amount=token_amount, transaction_hash=transaction_hash)
    db.add(transaction)

    db.commit()
    db.refresh(nft)
    db.refresh(transaction)

    # 6. Send Confirmation Email (async)
    email_body = f"Congratulations!\nYou have purchased NFT with ID: {nft.nft_id}\nTransaction Hash:{transaction_hash}"
    await utils.send_email(subject="NFT Purchase Confirmation", email_to=current_user.email, body=email_body)

    #Return NFT Details
    return {"message": "NFT purchased successfully", "nft": schemas.NFT.from_orm(nft), "transaction_hash": transaction_hash}

@app.get("/nft/{nft_id}", response_model=schemas.NFT)
async def get_nft(nft_id: str, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    """
    Retrieves NFT details, allowing retrieval in different formats (web, email, image).
    In a real application, you would check ownership.
    """
    # Input Validation
    if not isinstance(nft_id, str):
        raise HTTPException(status_code=400, detail="Invalid NFT ID.")

    nft = db.query(models.NFT).filter(models.NFT.nft_id == nft_id).first()
    if not nft:
        raise HTTPException(status_code=404, detail="NFT not found")

    return nft
```

*(No review comments for this file)*

*   ***\***\*backend/src/schemas.py\***\***\*

```python
# backend/src/schemas.py
from pydantic import BaseModel, validator
from typing import Optional

class UserCreate(BaseModel):
    email: str
    password: str

    @validator("email")
    def email_must_contain_at_symbol(cls, v):
        if "@" not in v:
            raise ValueError("Email must contain an @ symbol")
        return v

class User(BaseModel):
    id: int
    email: str

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class PurchaseRequest(BaseModel):
    user_solana_address: str
    token_amount: float

    @validator("token_amount")
    def token_amount_must_be_positive(cls, v):
        if v <= 0:
            raise ValueError("Token amount must be positive")
        return v

class NFTBase(BaseModel):
    name: str
    description: str

class NFTCreate(NFTBase):
    image_data: str  # Base64 encoded image or URL

class NFT(NFTBase):
    id: int
    nft_id: str #Unique identifier
    owner_id: int
    image_data: str
    metadata_url: Optional[str] = None

    class Config:
        orm_mode = True
```

*(No review comments for this file)*

*   ***\***\*backend/Dockerfile\***\***\*

```dockerfile
# Use a multi-stage build

# Builder stage
FROM python:3.9-slim-buster AS builder

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

COPY ./src /app/src

# Production stage
FROM python:3.9-slim-buster

WORKDIR /app

# Copy only necessary files from the builder stage
COPY --from=builder /app /app

# Set environment variables (example)
ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

*(No review comments for this file)*

*   ***\***\*backend/tests/test\_main.py\***\***\*

```python
# backend/tests/test_main.py
from fastapi.testclient import TestClient
from src.main import app
from src.database import get_db, Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import pytest
from src.models import User  # Import the User model

# Setup an in-memory SQLite database for testing
TEST_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(TEST_DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override the get_db dependency to use the test database session
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def test_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

def test_create_user(test_db):
    response = client.post(
        "/users",
        json={"email": "test@example.com", "password": "password123"},
    )
    assert response.status_code == 200
    assert response.json()["email"] == "test@example.com"

def test_login_for_access_token(test_db):
     # Create a user first
    client.post(
        "/users",
        json={"email": "testlogin@example.com", "password": "password123"},
    )

    response = client.post(
        "/token",
        data={"username": "testlogin@example.com", "password": "password123"},
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_get_user_me(test_db):
    # Create a user
    client.post(
        "/users",
        json={"email": "testme@example.com", "password": "password123"},
    )

    # Login to get a token
    token_response = client.post(
        "/token",
        data={"username": "testme@example.com", "password": "password123"},
    )
    access_token = token_response.json()["access_token"]

    # Get the user's profile with the token
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    assert response.json()["email"] == "testme@example.com"
```

*(No review comments for this file)*

*   ***\***\*frontend/package.json\***\***\*

```json
{
  "name": "premium-nft-frontend",
  "version": "0.1.0",
  "private": true,
  "dependencies": {
    "@emotion/react": "^11.11.3",
    "@emotion/styled": "^11.11.0",
    "@material-ui/core": "^4.12.4",
    "@material-ui/icons": "^4.11.3",
    "@mui/material": "^5.15.7",
    "@phantom-wallet/sdk": "^1.1.0",
    "@solana/web3.js": "^1.89.1",
    "axios": "^1.6.7",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.22.0",
    "react-scripts": "5.0.1",
    "web-vitals": "^2.1.4"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  },
  "eslintConfig": {
    "extends": [
      "react-app",
      "react-app/jest"
    ]
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ],
    "development": [
      "last 1 chrome version",
      "last 1 firefox version",
      "last 1 safari version"
    ]
  }
}
```

*(No review comments for this file)*

*   ***\***\*frontend/.env.example\***\***\*

```
REACT_APP_BACKEND_API_URL=http://localhost:8000
```

*(No review comments for this file)*

*   ***\***\*frontend/src/App.js\***\***\*

```jsx
// frontend/src/App.js
import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import LoginPage from './components/LoginPage';
import RegisterPage from './components/RegisterPage';
import NFTMarketplace from './components/NFTMarketplace';
import { AuthProvider } from './context/AuthContext';
import './App.css';
import { CssBaseline } from '@mui/material';

function App() {
  return (
    <AuthProvider>
        <CssBaseline /> {/* Provides a consistent baseline across different browsers */}
      <Router>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/" element={<NFTMarketplace />} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;
```

*(No review comments for this file)*

*   ***\***\*frontend/src/components/LoginPage.js\***\***\*

```jsx
// frontend/src/components/LoginPage.js
import React, { useState, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';
import axios from 'axios';
import { TextField, Button, Container, Typography, Grid } from '@mui/material';

function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const { setAuthToken } = useContext(AuthContext);
  const navigate = useNavigate();
  const [error, setError] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError(''); // Clear any previous errors
    try {
      //Use URLSearchParams correctly for x-www-form-urlencoded
      const params = new URLSearchParams();
      params.append('username', email);
      params.append('password', password);

      const response = await axios.post(`${process.env.REACT_APP_BACKEND_API_URL}/token`, params, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });

      setAuthToken(response.data.access_token);
      localStorage.setItem('token', response.data.access_token); // Store token in localStorage
      navigate('/');
    } catch (e) {
           let errorMessage = 'Login failed. Please check your credentials.';
            if (e.response && e.response.data && e.response.data.detail) {
                errorMessage = e.response.data.detail; // Capture the backend's error message
            } else if (e.message) {
                errorMessage = e.message;
            }
            setError(errorMessage); // Set the error state
            console.error('Login failed', e);
    }
  };

 return (
        <Container component="main" maxWidth="xs">
            <div>
                <Typography component="h1" variant="h5">
                    Login
                </Typography>
                {error && (
                    <Typography color="error" variant="body2" align="center">
                        {error}
                    </Typography>
                )}
                <form onSubmit={handleSubmit}>
                    <Grid container spacing={2}>
                        <Grid item xs={12}>
                            <TextField
                                variant="outlined"
                                required
                                fullWidth
                                id="email"
                                label="Email Address"
                                name="email"
                                autoComplete="email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                            />
                        </Grid>
                        <Grid item xs={12}>
                            <TextField
                                variant="outlined"
                                required
                                fullWidth
                                name="password"
                                label="Password"
                                type="password"
                                id="password"
                                autoComplete="current-password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                            />
                        </Grid>
                        <Grid item xs={12}>
                            <Button
                                type="submit"
                                fullWidth
                                variant="contained"
                                color="primary"
                            >
                                Log In
                            </Button>
                        </Grid>
                    </Grid>
                </form>
            </div>
        </Container>
    );
}

export default LoginPage;
```

*(No review comments for this file)*

*   ***\***\*frontend/src/components/RegisterPage.js\***\***\*

```jsx
// frontend/src/components/RegisterPage.js
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { TextField, Button, Container, Typography, Grid } from '@mui/material';

function RegisterPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();
    const [error, setError] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
      setError(''); //Clear previous errors
    try {
      await axios.post(`${process.env.REACT_APP_BACKEND_API_URL}/users`, {
        email: email,
        password: password
      });
      alert('Registration successful! Redirecting to login...');
      navigate('/login'); // Redirect to login page after successful registration
    } catch (e) {
            let errorMessage = 'Registration failed. Please try again.';
            if (e.response && e.response.data && e.response.data.detail) {
                errorMessage = e.response.data.detail; // Capture the backend's error message
            } else if (e.message) {
                errorMessage = e.message;
            }
            setError(errorMessage); // Set the error state
            console.error('Registration failed', e);
    }
  };

    return (
        <Container component="main" maxWidth="xs">
            <div>
                <Typography component="h1" variant="h5">
                    Register
                </Typography>
                 {error && (
                    <Typography color="error" variant="body2" align="center">
                        {error}
                    </Typography>
                )}
                <form onSubmit={handleSubmit}>
                    <Grid container spacing={2}>
                        <Grid item xs={12}>
                            <TextField
                                variant="outlined"
                                required
                                fullWidth
                                id="email"
                                label="Email Address"
                                name="email"
                                autoComplete="email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                            />
                        </Grid>
                        <Grid item xs={12}>
                            <TextField
                                variant="outlined"
                                required
                                fullWidth
                                name="password"
                                label="Password"
                                type="password"
                                id="password"
                                autoComplete="new-password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                            />
                        </Grid>
                        <Grid item xs={12}>
                            <Button
                                type="submit"
                                fullWidth
                                variant="contained"
                                color="primary"
                            >
                                Register
                            </Button>
                        </Grid>
                    </Grid>
                </form>
            </div>
        </Container>
    );
}

export default RegisterPage;
```

*(No review comments for this file)*

*   ***\***\*frontend/src/components/NFTMarketplace.js\***\***\*

```jsx
// frontend/src/components/NFTMarketplace.js
import React, { useState, useEffect, useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
import axios from 'axios';
import { Connection, PublicKey } from '@solana/web3.js';

function NFTMarketplaceOkay, I understand. I will take the provided code and the code review, incorporate all the suggested improvements, and produce a single, complete, and fully functional code output with explanations.

**Please provide me with the first iteration of the code and the code review.**

Once you provide that, I'll do my best to:

1.  **Combine the code and the suggestions.**
2.  **Resolve any conflicting suggestions.**
3.  **Ensure the code is complete and runnable.**
4.  **Provide a thoroughly commented and explained code output.**

I am ready when you are!
