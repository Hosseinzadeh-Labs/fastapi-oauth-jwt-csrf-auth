# 🔐 Secure Authentication System (FastAPI)

A production-style authentication system focused on real-world security concepts.

---

## 🚀 Features

- Google OAuth 2.0 authentication
- JWT-based authentication (Access & Refresh Tokens)
- Secure session management using HttpOnly cookies
- CSRF protection (Double Submit Cookie Pattern)
- Token expiration and refresh flow

---

## 🛡️ Security Implementation

This project is built with a strong focus on application security:

- JWT signature validation (prevents token tampering)
- CSRF protection against cross-site attacks
- Secure cookie configuration (HttpOnly, SameSite)
- Separation of access and refresh tokens

---

## 🧪 Attack Simulations (Tested)

This system was tested against real-world attack scenarios:

- ❌ JWT Tampering → Rejected
- ❌ Missing CSRF Token → Blocked
- ❌ Fake CSRF Token → Blocked

---

## 🧠 Key Takeaways

- Authentication alone is not enough
- Every request must be verified and trusted
- Cookies introduce CSRF risks
- Proper token handling is critical for security

---

## 🛠️ Tech Stack

- FastAPI
- Python
- OAuth 2.0 (Google)
- JWT (python-jose)

---

## 📌 Future Improvements

- HTTPS secure cookies (secure=True)
- Token rotation
- Role-based access control (RBAC)

---

## 🔄 Authentication Flow (Step-by-Step)

1. User logs in via Google OAuth
2. Backend receives authorization code
3. Google returns ID token
4. Backend verifies ID token
5. Access token (short-lived) is issued
6. Refresh token (long-lived) is issued
7. Tokens stored securely in HttpOnly cookies
8. CSRF token protects state-changing requests


## 👨‍💻 Author

Built as part of my journey into Application Security (AppSec)
