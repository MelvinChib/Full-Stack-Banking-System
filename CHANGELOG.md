# Changelog

All notable changes to SwiftBank.

## [2.0.0] - 2025-01

### Security
- Removed all hardcoded credentials (externalized to environment variables)
- Enhanced SQL injection and XSS protection
- Improved error handling (no sensitive data leakage)
- Added security headers (HSTS, CSP, X-Frame-Options)
- CSRF protection enabled

### Bug Fixes
- Changed Java 21 to Java 17 for compatibility
- Fixed validation constraints in DTOs
- Removed redundant getters/setters (Lombok handles this)
- Fixed frontend environment variable usage

### Project Structure
- Removed mixed frontend/backend code
- Added startup helper scripts
- Created environment templates (.env.example)

### Configuration
- Profile-specific configs (test, dev, prod)
- Externalized all sensitive data
- Enhanced Docker setup with health checks


## [1.2.0] - 2024-01
- Statement export (PDF, CSV, Text)
- Date range filtering

## [1.1.0] - 2024-01
- AI customer support chatbot
- OpenAI integration

## [1.0.0] - 2024-01
- Initial release
- JWT authentication
- Multi-account management
- Transaction processing
- Bill payments and budget tracking
- React 18 + Spring Boot 3.2

---

**Developer:** Melvin Musonda Chibanda (melvinchibanda@gmail.com)

**License:** MIT
