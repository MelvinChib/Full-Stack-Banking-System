# 🏦 SwiftBank - Complete Banking Application

**Production-ready banking platform** that lets you manage accounts, transfer money, pay bills, track budgets, and export statements - all with **bank-grade security**. Features AI customer support, rate limiting, audit trails, and comprehensive documentation. Ready to run in 5 minutes with H2, scales to PostgreSQL for production.

![SwiftBank](https://img.shields.io/badge/SwiftBank-Banking-blue.svg)
![Java](https://img.shields.io/badge/Java-17-orange.svg)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2-brightgreen.svg)
![React](https://img.shields.io/badge/React-18-blue.svg)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-12+-blue.svg)

## 🌟 **Key Features**

### 🔐 **Authentication & Security**
- ✅ JWT-based authentication with secure token management
- ✅ Password encryption (BCrypt with strength 12)
- ✅ Role-based access control (User/Admin)
- ✅ Input validation and sanitization
- ✅ CORS protection and security headers

### 🏦 **Core Banking Features**
- ✅ **Multi-Account Management**: Checking, Savings, Credit Card, Loan, Investment accounts
- ✅ **Account Operations**: Create, view, update, and deactivate accounts
- ✅ **Transaction Processing**: Comprehensive transaction management
- ✅ **Bill Management**: Schedule and pay bills with auto-pay options
- ✅ **Budget Tracking**: Category-based budgeting with alerts
- ✅ **Fund Transfers**: Internal and external money transfers

### 🤖 **AI Customer Support**
- ✅ **Intelligent Chatbot**: AI-powered customer support with natural language processing
- ✅ **Context-Aware Responses**: Banking-specific knowledge base
- ✅ **Quick Help Topics**: Pre-defined common queries
- ✅ **Human Agent Escalation**: Automatic detection of complex issues
- ✅ **Category-Based Support**: Organized support by banking topics

### 📄 **Advanced Statement Export**
- ✅ **PDF Export**: Professional formatted statements with bank letterhead
- ✅ **CSV Export**: Spreadsheet-compatible data for analysis
- ✅ **Text Export**: Plain text format with transaction summaries
- ✅ **Date Range Filtering**: Custom period selection
- ✅ **Account Selection**: Export statements for any account

### 🎨 **Modern Frontend**
- ✅ **React 18**: Latest React features with hooks and context
- ✅ **Tailwind CSS**: Responsive, utility-first styling
- ✅ **FNB-inspired theme**: Light, professional teal/white palette with orange accents
- ✅ **Real-time Updates**: Dynamic UI updates
- ✅ **Mobile Responsive**: Optimized for all device sizes
- ✅ **Intuitive UX**: User-friendly interface design

### 🚀 **Backend Architecture**
- ✅ **Spring Boot 3.2**: Modern Java framework
- ✅ **Layered Architecture**: Clear separation of concerns
- ✅ **JPA/Hibernate**: Advanced ORM with relationships
- ✅ **Global Exception Handling**: Structured error responses
- ✅ **API Documentation**: Swagger/OpenAPI integration

## 🏗️ **Architecture Overview**

Key backend behavior for onboarding (test profile with H2):
- When a user registers, the system:
  - Validates credentials, stores user in H2 with hashed password (BCrypt)
  - Generates an account number (prefix MBZ) and creates a default CHECKING account
  - Sends an email with the account number and sign-in steps

Statement exports:
- GET /accounts/{id}/statement/pdf|csv|text?fromDate=&toDate=
- Requires Authorization Bearer token

Customer Support:
- POST /customer-support/chat accepts a message and returns an answer; uses OpenAI if configured, otherwise a fallback.

```
SwiftBank App/
├── 📁 backend/                 # Spring Boot Backend
│   ├── 🔧 src/main/java/       # Java source code
│   │   └── com/bankinghub/backend/
│   │       ├── 🏛️ controller/   # REST Controllers
│   │       ├── 🔧 service/      # Business Logic
│   │       ├── 🗃️ repository/   # Data Access Layer
│   │       ├── 📊 model/        # JPA Entities
│   │       ├── 🔄 dto/          # Data Transfer Objects
│   │       ├── 🔐 security/     # Security Configuration
│   │       └── ⚙️ config/       # Application Configuration
│   ├── 📋 src/main/resources/
│   │   └── application.yml     # Configuration Properties
│   └── 🔨 pom.xml              # Maven Dependencies
│
├── 📁 frontend/                # React Frontend
│   ├── 📁 src/
│   │   ├── 🧩 components/      # React Components
│   │   ├── 🔌 services/        # API Integration
│   │   ├── 🎨 styles/          # CSS & Styling
│   │   └── 📱 pages/           # Application Pages
│   ├── 📁 public/              # Static Assets
│   └── 📦 package.json         # Node Dependencies
│
└── 📖 README.md               # This file
```

## ☁️ **Push to GitHub**

### **Initial Setup**
```bash
# Initialize git (if not already done)
git init
git add .
git commit -m "v2.0.0 - Security hardened production-ready release"

# Create GitHub repository (via web or CLI)
gh repo create FullStackBankingSystem --public --source=. --remote=origin

# Or add existing remote
git remote add origin https://github.com/<your-username>/FullStackBankingSystem.git

# Push to GitHub
git branch -M main
git push -u origin main
```

### **Using Personal Access Token (PAT)**
```bash
# Create PAT at: https://github.com/settings/tokens
# Scopes needed: repo, workflow

# Configure git credential helper
git config --global credential.helper store

# Push (will prompt for PAT)
git push -u origin main
# Username: <your-github-username>
# Password: <your-PAT-token>
```

### **Using GitHub CLI (Recommended)**
```bash
# Install GitHub CLI
brew install gh  # macOS
# sudo apt install gh  # Linux

# Authenticate
gh auth login

# Push
git push -u origin main
```

## 🚀 **New Features (v2.0.0 - January 2025)**

This release includes the following end-user features and developer integrations:

- Statement downloads (PDF, CSV, Text) per account with date range filters
- Customer support chat (AI-backed, with graceful fallback if no API key)
- Google Analytics integration via Vite env variable (optional)
- User registration with onboarding flow:
  - Store users in H2 (test profile) with JWT auth and roles
  - Automatically create a default account and generate an account number
  - Send onboarding email with account number and sign-in instructions (no plaintext password)
- Ready-to-run locally and with Docker

Configuration quick refs:
- VITE_API_URL: Frontend base API, e.g. http://localhost:8080/api/v1
- VITE_ENABLE_DEMO: Set to true to enable demo login fallback (email: demo@bankinghub.com, password: demo123) when backend is unavailable
- VITE_GA_MEASUREMENT_ID: Google Analytics G-XXXX value (optional)
- DB_USERNAME/DB_PASSWORD: Backend db creds (dev/prod profiles), H2 used in test
- OPENAI_API_KEY: Optional key for AI customer support

## 🚀 **Quick Start Guide**

### **Prerequisites**
- ☕ **Java 17** (Required - not Java 21)
- 🔧 **Maven 3.8+**
- 🐘 **PostgreSQL 12+** (or H2 for testing)
- 🟢 **Node.js 16+** and **npm/yarn**
- 📝 **Git**

### **1. Clone the Repository**
```bash
git clone https://github.com/<your-username>/FullStackBankingSystem.git
cd FullStackBankingSystem-master
```

### **2. Backend Setup & Run**

#### **Option A: Quick Start with Helper Script (Recommended)**
```bash
cd backend
chmod +x run-backend.sh
./run-backend.sh
```

#### **Option B: Manual Setup**

**Step 1: Verify Java 17**
```bash
java -version  # Should show Java 17
# If not, set JAVA_HOME:
export JAVA_HOME=$(/usr/libexec/java_home -v 17)  # macOS
# export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64  # Linux
```

**Step 2: Configure Environment (Optional)**
```bash
cd backend

# For PostgreSQL (production):
export DB_USERNAME=your_db_username
export DB_PASSWORD=your_db_password
export JWT_SECRET=your-256-bit-secret-key-here
export OPENAI_API_KEY=your-openai-key  # Optional for AI support

# For H2 (testing) - no configuration needed
```

**Step 3: Build & Run**
```bash
# Clean and compile
mvn clean install

# Run with H2 in-memory database (testing/development)
mvn spring-boot:run -Dspring-boot.run.profiles=test

# OR run with PostgreSQL (production)
mvn spring-boot:run -Dspring-boot.run.profiles=prod
```

**Troubleshooting Backend:**
```bash
# If port 8080 is already in use:
lsof -ti:8080 | xargs kill -9

# If Java version mismatch:
mvn clean install  # Recompile with correct Java version
```

**Backend will be available at:** `http://localhost:8080/api/v1`

### **3. Frontend Setup & Run**

#### **Option A: Quick Start with Helper Script (Recommended)**
```bash
cd frontend
chmod +x run-frontend.sh
./run-frontend.sh
```

#### **Option B: Manual Setup**

**Step 1: Install Dependencies**
```bash
cd frontend
npm install
```

**Step 2: Configure Environment**
```bash
# Copy example environment file
cp .env.example .env

# Edit .env file with your settings:
VITE_API_URL=http://localhost:8080/api/v1
VITE_ENABLE_DEMO=true
# VITE_GA_MEASUREMENT_ID=G-XXXXXXXXXX  # Optional
```

**Step 3: Start Development Server**
```bash
npm run dev
# OR
npm start
```

**Frontend will be available at:** `http://localhost:5173`

### **4. Access the Application**

- 🌐 **Frontend**: http://localhost:5173
- 🔧 **Backend API**: http://localhost:8080/api/v1
- 📚 **API Documentation**: http://localhost:8080/swagger-ui.html
- ❤️ **Health Check**: http://localhost:8080/actuator/health

#### **Default Test Credentials (H2 Test Profile)**
When running with `-Dspring-boot.run.profiles=test`, you can register a new account or use demo mode:

**Demo Mode (if VITE_ENABLE_DEMO=true):**
- Email: Set in `.env` as `VITE_DEMO_EMAIL`
- Password: Set in `.env` as `VITE_DEMO_PASSWORD`

**Or Register New Account:**
1. Go to http://localhost:5173/register
2. Fill in the registration form
3. System auto-creates a CHECKING account
4. Check console for account number (email sent in production)

#### **Frontend Routes**
| Route | Description |
|-------|-------------|
| `/login` | User authentication (JWT) |
| `/register` | New account registration |
| `/account-dashboard` | Account overview, insights, alerts |
| `/account-details` | Transactions, filters, statement exports |
| `/bill-pay` | Bill management and payments |
| `/budget-tracker` | Budget management and goals |
| `/transfer-funds` | Money transfers (internal/external) |
| `/support` | AI-powered customer support chat |

## 📱 **Application Features Demo**

### **1. User Registration & Login**
```bash
# Register new user
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "John",
    "lastName": "Doe", 
    "email": "john@example.com",
    "password": "SecurePass123!",
    "confirmPassword": "SecurePass123!"
  }'

# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

### **2. Account Management**
- On registration, the backend auto-creates a default CHECKING account and sends the user their generated account number by email.
- You can still manage accounts via the API.

```bash
# Create new account
curl -X POST http://localhost:8080/api/v1/accounts \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "accountType": "CHECKING",
    "accountName": "My Checking Account",
    "initialBalance": 1000.00
  }'

# Get user accounts
curl -X GET http://localhost:8080/api/v1/accounts \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### **3. AI Customer Support**
- Works out-of-the-box. If OPENAI_API_KEY is not set, responses come from a built-in fallback (non-AI) so the endpoint remains usable in development.

```bash
# Ask AI support question
curl -X POST http://localhost:8080/api/v1/customer-support/chat \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "How do I reset my password?"
  }'
```

### **4. Export Statements**
```bash
# Export PDF statement
curl -X GET "http://localhost:8080/api/v1/accounts/1/statement/pdf?fromDate=2024-01-01T00:00:00&toDate=2024-12-31T23:59:59" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  --output statement.pdf

# Export CSV statement  
curl -X GET "http://localhost:8080/api/v1/accounts/1/statement/csv" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  --output statement.csv
```

## 🔧 **Configuration**

### **Backend Configuration**

**Environment Variables:**
```bash
# Database (PostgreSQL)
DB_USERNAME=your_db_username
DB_PASSWORD=your_db_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=swiftbank

# Security
JWT_SECRET=your-256-bit-secret-key-minimum-32-characters
JWT_EXPIRATION=86400000  # 24 hours in milliseconds

# AI Support (Optional)
OPENAI_API_KEY=sk-your-openai-api-key

# Email (Optional - for production)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

**Application Profiles:**
- `test` - H2 in-memory database (no setup required)
- `dev` - PostgreSQL development database
- `prod` - PostgreSQL production database with enhanced security

**Configuration Files:**
- `backend/src/main/resources/application.yml` - Main configuration
- `backend/src/main/resources/application-test.yml` - Test profile (H2)
- `backend/src/main/resources/application-dev.yml` - Development profile
- `backend/src/main/resources/application-prod.yml` - Production profile

### **Frontend Configuration**

**Environment Variables (.env):**
```bash
# API Configuration
VITE_API_URL=http://localhost:8080/api/v1

# Demo Mode (Development Only)
VITE_ENABLE_DEMO=true
VITE_DEMO_EMAIL=demo@melvinbank.com
VITE_DEMO_PASSWORD=Demo123!
VITE_DEMO_USER_NAME=Demo User

# Analytics (Optional)
VITE_GA_MEASUREMENT_ID=G-XXXXXXXXXX

# App Info
VITE_APP_NAME=SwiftBank
VITE_APP_VERSION=2.0.0
```

**Important:** Never commit `.env` files with real credentials. Use `.env.example` as a template.

## 🌍 **Deployment**

### **Docker Deployment (Recommended)**

**Prerequisites:**
- Docker 20.10+
- Docker Compose 2.0+

**Step 1: Configure Environment**
```bash
# Copy and edit environment file
cp .env.docker .env
# Edit .env with your production values
```

**Step 2: Build and Run**
```bash
# Build and start all services
docker-compose up -d --build

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

**Services:**
- Frontend: http://localhost:3000
- Backend: http://localhost:8080
- PostgreSQL: localhost:5432

### **Manual Production Deployment**

#### **Backend Deployment**
```bash
cd backend

# Set production environment variables
export SPRING_PROFILES_ACTIVE=prod
export DB_USERNAME=prod_user
export DB_PASSWORD=secure_password
export JWT_SECRET=production-secret-key-256-bits

# Build JAR
mvn clean package -DskipTests

# Run application
java -jar -Dspring.profiles.active=prod target/backend-0.0.1-SNAPSHOT.jar
```

#### **Frontend Deployment**
```bash
cd frontend

# Set production API URL
echo "VITE_API_URL=https://api.melvinbank.com/api/v1" > .env

# Build for production
npm run build

# Deploy dist/ folder to:
# - AWS S3 + CloudFront
# - Netlify
# - Vercel
# - Nginx server
```

#### **Nginx Configuration Example**
```nginx
server {
    listen 80;
    server_name melvinbank.com;
    root /var/www/melvinbank/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 📊 **API Documentation**

### **Core Endpoints**

#### **🔐 Authentication**
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `GET /auth/me` - Get current user profile

#### **🏦 Account Management**
- `GET /accounts` - List user accounts
- `POST /accounts` - Create new account
- `GET /accounts/{id}` - Get account details
- `PUT /accounts/{id}` - Update account
- `DELETE /accounts/{id}` - Delete account

#### **🤖 Customer Support**
- `POST /customer-support/chat` - AI chat support
- `GET /customer-support/categories` - Support categories
- `GET /customer-support/quick-help` - Quick help topics

#### **📄 Statement Export**
- `GET /accounts/{id}/statement/pdf` - Export PDF statement
- `GET /accounts/{id}/statement/csv` - Export CSV statement
- `GET /accounts/{id}/statement/text` - Export text statement

## 🧪 **Testing**

### **Backend Testing**
```bash
cd backend

# Run all tests
mvn test

# Run with test profile (H2 database)
mvn test -Dspring.profiles.active=test

# Run with coverage
mvn clean test jacoco:report
```

### **Frontend Testing**
```bash
cd frontend

# Run unit tests
npm test

# Run with coverage
npm test -- --coverage

# Run E2E tests
npm run test:e2e
```

## 📈 **Performance & Monitoring**

- **Backend Monitoring**: Spring Actuator endpoints at `/actuator/health`, `/actuator/metrics`
- **Database Connection Pooling**: HikariCP for optimal performance
- **Caching**: Spring Cache with configurable providers
- **Logging**: Structured logging with SLF4J and Logback

## 🔒 **Security Features**

- **JWT Authentication**: Stateless authentication with configurable expiration
- **Password Security**: BCrypt hashing with strength 12
- **Input Validation**: Jakarta Bean Validation with custom validators
- **SQL Injection Protection**: Parameterized queries via JPA
- **CORS Protection**: Configurable cross-origin resource sharing
- **Rate Limiting**: Built-in Spring Security protections

## 🛠️ **Technology Stack**

### **Backend Technologies**
| Category | Technology | Version |
|----------|------------|---------|
| **Language** | Java | 17 |
| **Framework** | Spring Boot | 3.2.0 |
| **Security** | Spring Security + JWT | 6.x |
| **Database** | PostgreSQL / H2 | 12+ / 2.x |
| **ORM** | JPA/Hibernate | 6.x |
| **Build Tool** | Maven | 3.8+ |
| **Documentation** | SpringDoc OpenAPI | 2.2.0 |
| **PDF Generation** | iText7 | 7.2.5 |

### **Frontend Technologies**
| Category | Technology | Version |
|----------|------------|---------|
| **Language** | JavaScript/JSX | ES2022 |
| **Framework** | React | 18 |
| **Build Tool** | Vite | 4.x |
| **Styling** | Tailwind CSS | 3.x |
| **State Management** | React Context/Hooks | 18 |
| **HTTP Client** | Fetch API | Native |
| **Routing** | React Router | 6.x |

## 👨‍💻 **Development Team**

**Lead Developer:** Melvin Musonda Chibanda
- 📧 Email: melvinchibanda@gmail.com
- 🐙 GitHub: [melvinchibanda]

## 📄 **License**

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## 🤝 **Contributing**

1. 🍴 Fork the repository
2. 🌿 Create a feature branch (`git checkout -b feature/amazing-feature`)
3. ✅ Commit your changes (`git commit -m 'Add amazing feature'`)
4. 📤 Push to the branch (`git push origin feature/amazing-feature`)
5. 🔀 Open a Pull Request

## 📞 **Support**

For support and questions:
- 📧 **Email**: melvinchibanda@gmail.com
- 📞 **Phone**: +260-XXX-XXXX
- 🎫 **Issues**: Create an issue in this repository
- 📚 **Documentation**: Check the `/docs` folder for detailed documentation

## 🔄 **Version History**

| Version | Date | Description |
|---------|------|-------------|
| **v1.0.0** | 2024-01 | Initial release with core banking features |
| **v1.1.0** | 2024-01 | Added AI customer support |
| **v1.2.0** | 2024-01 | Added statement export functionality |
| **v2.0.0** | 2025-01 | 🔒 **Security hardening**, removed hardcoded credentials, fixed Java 17 compatibility, enhanced error handling, production-ready configuration |

---

## 🔒 **Security Features (v2.0)**

✅ **All security vulnerabilities fixed:**
- No hardcoded credentials (all externalized to environment variables)
- SQL injection protection (parameterized queries via JPA)
- XSS protection (input sanitization and validation)
- CSRF protection (Spring Security)
- Secure password hashing (BCrypt strength 12)
- JWT token-based authentication
- Rate limiting and brute force protection
- Comprehensive error handling without information leakage
- Security headers (HSTS, X-Frame-Options, CSP)

## 🐛 **Troubleshooting**

### **Backend Issues**

**Port 8080 already in use:**
```bash
lsof -ti:8080 | xargs kill -9
```

**Java version mismatch:**
```bash
# Verify Java 17
java -version

# Set JAVA_HOME (macOS)
export JAVA_HOME=$(/usr/libexec/java_home -v 17)

# Recompile
cd backend
mvn clean install
```

**Database connection failed:**
```bash
# Use H2 for testing (no setup)
mvn spring-boot:run -Dspring-boot.run.profiles=test

# Or check PostgreSQL is running
psql -U postgres -c "SELECT version();"
```

### **Frontend Issues**

**Port 5173 already in use:**
```bash
lsof -ti:5173 | xargs kill -9
```

**API connection failed:**
```bash
# Check backend is running
curl http://localhost:8080/actuator/health

# Verify .env configuration
cat frontend/.env
```

**Dependencies installation failed:**
```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
```

## 📚 **Additional Documentation**

- `QUICK_START.md` - Fast setup guide
- `PROJECT_STRUCTURE.md` - Architecture details
- `SECURITY_CONFIGURATION.md` - Production security setup
- `FIXES_APPLIED.md` - All fixes in v2.0
- `frontend/.env.example` - Frontend environment template
- `backend/src/main/resources/application*.yml` - Backend configuration

## 🌟 **Why Choose SwiftBank?**

- 🏆 **100% Local**: Built specifically for Zambian banking needs
- 🔒 **Bank-Grade Security**: Enterprise-level security protocols (v2.0 hardened)
- 🤖 **AI-Powered**: Modern AI customer support system
- 📱 **Mobile-First**: Responsive design for all devices
- ⚡ **Fast & Reliable**: High-performance architecture
- 🔧 **Developer-Friendly**: Well-documented and maintainable code
- 🌍 **Open Source**: Community-driven development
- ✅ **Production-Ready**: Fully tested and security-audited

**SwiftBank - Banking Made Simple & Secure** 🇿🇲

---

*Built with ❤️ in Zambia by Melvin Musonda Chibanda*