# Overview

Qualitics Production is a premium e-commerce platform for digital solutions, built as a high-performance web application with a focus on speed, security, and user experience. The platform features a comprehensive product catalog, secure authentication, shopping cart functionality, payment processing via PayPal, and an advanced loyalty points system. It includes user management, analytics dashboard, ban/security systems, and administrative controls. The application emphasizes performance optimization with sub-400ms load times and enterprise-grade security features.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

**Frontend Architecture**
- Pure web stack using HTML5, CSS3, and vanilla JavaScript (no frameworks for maximum performance)
- Mobile-first responsive design with modern CSS Grid and Flexbox
- Component-based architecture with reusable CSS classes and JavaScript modules
- Optimized asset loading with minification, preloading, and lazy loading strategies
- Client-side routing and state management for single-page application feel

**Backend Architecture**
- Node.js with Express.js for the web server and API endpoints
- RESTful API design with structured route handling in `/server/routes.js`
- Dual storage strategy: File-based storage for development/simple deployments and database integration for production
- JWT-based authentication with Google OAuth integration
- Modular architecture with separate concerns: routes, storage, database, and schema definitions

**Database Design**
- Drizzle ORM with PostgreSQL (Neon serverless) for production database
- Schema-first approach with TypeScript/JavaScript dual compatibility
- Two main entities: `products` (catalog management) and `users` (authentication/profiles)
- Built-in migration system using Drizzle Kit for schema evolution

**Authentication & Security**
- Google OAuth 2.0 integration for secure user authentication
- JWT token-based session management with configurable timeouts
- Advanced ban system with IP tracking and email-based restrictions
- Comprehensive security headers (CSP, XSS protection, referrer policy)
- Client-side security monitoring and suspicious activity detection

**E-commerce Features**
- Dynamic product catalog with categories, pricing, and discount systems
- Real-time shopping cart with quantity controls and price calculations
- Quality Points loyalty system (1 point per purchase, 2% discount per point)
- Premium membership tier with enhanced benefits and 2x point multipliers
- PayPal integration for secure payment processing

**Analytics & Monitoring**
- Real-time metrics dashboard with Chart.js visualizations
- User behavior tracking and engagement analytics
- Performance monitoring with GTmetrix integration
- System logging and audit trails for administrative oversight

# External Dependencies

**Payment Processing**
- PayPal SDK for secure transaction handling and payment capture
- Configured with sandbox/production environment switching

**Authentication Services**
- Google OAuth 2.0 API for user sign-in and profile management
- Google Client Library for frontend authentication flows

**Database & Infrastructure**
- Neon Database (serverless PostgreSQL) for production data storage
- WebSocket support for real-time features via `ws` library
- Drizzle ORM for type-safe database operations and migrations

**Communication & Notifications**
- EmailJS for contact forms and user notifications
- SMTP integration for administrative alerts and purchase confirmations

**Analytics & Monitoring**
- Plausible Analytics for privacy-friendly website analytics
- Chart.js for dashboard data visualizations and reporting
- Custom performance monitoring with GTmetrix API integration

**Security & Validation**
- Zod library for runtime type validation and schema enforcement
- bcryptjs for password hashing and security operations
- CORS middleware for cross-origin request handling

**Development & Build Tools**
- Custom minification system for CSS and JavaScript optimization
- Nodemon for development server auto-reloading
- Drizzle Kit for database schema management and migrations