# 🌐 Spring Security & JWT 정리

## 🎯 목적
📘 [Modern API Development with Spring 6 and Spring Boot 3](https://github.com/PacktPublishing/Modern-API-Development-with-Spring-6-and-Spring-Boot-3/tree/main/Chapter06) 를 공부하며,  
Chapter 6의 내용을 개인적으로 정리하고 요약한 문서입니다.

---
### 1️⃣ Spring Security 개요

🔹 **Spring Security 란?**  
Spring 기반 애플리케이션의 **인증(Authentication)** 과 **인가(Authorization)** 를 관리하는 보안 프레임워크입니다.  
🔖 [_Boilerplate Code_](#-boilerplatecode)를 직접 작성하지 않고도 **표준화된 보안 기능(인증, 인가, 세션 관리, CSRF 보호 등)을 손쉽게 구현할 수 있도록 지원하는 라이브러리 기반 프레임워크**입니다.  
➡ **즉, 보안 관련 로직을 직접 구현할 필요 없이, Spring Security가 제공하는 기능을 활용하여 안전한 애플리케이션을 개발할 수 있습니다.**  

#### 🔹 주요 기능
✅ **인증(Authentication)** → 사용자가 누구인지 확인  
✅ **인가(Authorization)** → 사용자가 특정 리소스에 접근할 수 있는지 결정  
✅ **보안 필터(Security Filters)** → 요청과 응답을 가로채 보안 검사 수행  
✅ **비밀번호 암호화(BCrypt)** → 안전한 비밀번호 저장  
✅ **CSRF/XSRF 보호** → CSRF 공격 방지  

#### 🔹 SecurityFilterChain의 역할
- 요청을 가로채어 **인증(Authentication)과 인가(Authorization)** 수행
- **Pre-filter(프리 필터)** → 요청이 컨트롤러로 전달되기 전에 적용  
- **Post-filter(포스트 필터)** → 응답이 반환되기 전에 적용  

🔹 **Spring Security의 라이브러리 및 Gradle 설정** 
 
### 2️⃣ Spring Security 요청 처리 흐름  
🔹 **DispatcherServlet과 요청 흐름**  
- 클라이언트 → DispatcherServlet → Security Filter → 컨트롤러 → 서비스 → DB  
- 사용자가 로그인 정보를 입력 → 보안 시스템(Spring Security)이 이를 확인 → 로그인 성공 후 사용자의 정보를 DB에서 가져옴 → 해당 정보에 따라 접근 권한을 결정

🔹 **SecurityFilterChain의 역할 및 필터 흐름**  
- SecurityFilterChain이 요청을 가로채고 **인증(Authentication)과 인가(Authorization)을 수행**  
- `SecurityFilterChain` 내부에서 동작하는 필터:
  - **Pre-filter(프리 필터)** → 요청이 컨트롤러로 전달되기 전에 적용 (예: 인증 필터, CORS 필터)  
  - **Post-filter(포스트 필터)** → 컨트롤러에서 처리된 응답이 반환되기 전에 적용 (예: 응답 데이터 필터링, 접근 권한 검사)  

🔹 **보안 필터 주요 예제**  
- `@PreAuthorize("hasRole('ADMIN')")` → 요청 전에 특정 권한을 요구하는 필터  
- `@PostAuthorize("returnObject.owner == authentication.name")` → 응답 반환 후 특정 조건 검사  
- `@PreFilter("filterObject.isActive")` → 리스트에서 특정 조건을 만족하는 항목만 필터링  
- `@PostFilter("filterObject.owner == authentication.name")` → 응답으로 전달될 데이터 필터링

---

### 3️⃣ JWT (JSON Web Token) 기반 인증

**JWT란?**  
토큰 기반 인증 방식으로 **Stateless(상태 없음) 인증 방식**을 제공하며, 클라이언트가 로그인하면 JWT를 발급받고 이후 요청마다 JWT를 포함하여 인증 수행합니다.

#### 🔹 JWT 구조
| 구성 요소 | 설명 | 예제 |
|--------|------|------|
| **헤더 (Header)** | 토큰의 종류와 암호화 방식 | JWT, HS256 |
| **페이로드 (Payload)** | 사용자 정보 (ID, 권한 등) | { "user": "John", "role": "admin" } |
| **서명 (Signature)** | 위변조 방지 서명 | 암호화된 해시값 |

- **Header(헤더)** → 서명 알고리즘, 토큰 유형 정보 포함
- **Payload(페이로드)** → 클레임(등록, 공개, 비공개) 포함
- **Signature(서명)** → 무결성을 보장하는 서명

### 1.1 페이로드의 클레임(Claims) 정의 및 종류
클레임(Claims)은 토큰에 포함된 데이터로, 다음과 같은 유형이 있음:

#### 1) **등록된 클레임(Registered Claims)**
JWT 표준에 정의된 클레임으로, 사용이 권장됨.
- iss (Issuer) - 발급자
- sub (Subject) - 토큰의 주제 (사용자 ID 등)
- aud (Audience) - 토큰을 사용할 대상
- exp (Expiration) - 만료 시간
- nbf (Not Before) - 특정 시간 이전에는 토큰이 유효하지 않음
- iat (Issued At) - 토큰이 발급된 시간
- jti (JWT ID) - 토큰의 고유 식별자

#### 2) **공개 클레임(Public Claims)**
사용자가 정의한 클레임으로, 충돌을 방지하기 위해 공식적으로 등록된 네임스페이스 사용 권장.
예: https://myapp.com/user_role

#### 3) **비공개 클레임(Private Claims)**
특정 애플리케이션이나 시스템 내부에서만 사용되는 클레임.
예: { "user_id": "12345", "role": "admin" }

#### 🔹 JWT vs 세션 기반 인증 비교
| 비교 항목 | JWT | 세션 기반 인증 |
|----------|-----|---------------|
| 저장 방식 | 클라이언트 측 (토큰 저장) | 서버 측 (세션 저장) |
| 확장성 | 높음 (Stateless) | 낮음 (서버 메모리 부담) |
| 보안성 | 토큰 탈취 시 위험 | 세션 하이재킹 위험 |

---

## 🔐 OAuth 2.0 개요

OAuth 2.0은 다양한 프레임워크에서 사용되며, 대표적으로 다음과 같은 환경에서 작동함:
- **Spring Security** (Java)
- **Express.js + Passport.js** (Node.js)
- **Django OAuth Toolkit** (Python)

### 🔹 주요 개념
- **리소스 소유자(Resource Owner)** → 사용자
- **클라이언트(Client)** → 사용자 대신 리소스를 요청하는 애플리케이션
- **인증 서버(Authorization Server)** → 사용자를 인증하고 액세스 토큰 발급
- **리소스 서버(Resource Server)** → 보호된 리소스를 제공

### 🔹 OAuth 2.0 동작 방식
1. 사용자가 클라이언트 앱에 로그인 요청
2. 클라이언트가 인증 서버에 권한 요청
3. 인증 서버가 사용자 인증 후 권한 부여 코드 발급
4. 클라이언트가 액세스 토큰 요청
5. 인증 서버가 액세스 토큰 발급
6. 클라이언트가 리소스 서버에 액세스 토큰 전달 후 보호된 리소스 요청
7. 
---

### 4️⃣ 보안 강화 및 권한 부여

#### 🔹  **유저 구분과 권한 부여 (RBAC - Role-Based Access Control)**
✅ `@Secured("ROLE_ADMIN")` → 특정 역할을 가진 사용자만 접근 가능  
✅ `@PreAuthorize("hasRole('USER')")` → 실행 전 권한 체크  
✅ `@PostAuthorize("returnObject.owner == authentication.name")` → 실행 후 반환 값 검증  

#### 🔹 비밀번호 해싱 (BCrypt)
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

#### 🔹 CSRF/XSRF 보호
```java
http.csrf().disable();
```

#### 🔹 CORS (Cross-Origin Resource Sharing)
```java
@CrossOrigin(origins = "https://example.com")
```

#### 🔹 RSA & JWT 서명
- JWT를 서명하고 검증할 때 **RSA 공개 키/개인 키 암호화**를 사용할 수 있음

---

## 📖 보안 개념 쉽게 이해하기

### 🔹 불투명 토큰(Opaque Token) vs JWT
| 비교 항목 | 불투명 토큰 (Opaque Token) | JWT |
|----------|-----------------|------|
| 저장 방식 | 서버에서 관리 | 클라이언트가 직접 보관 |
| 검증 방식 | 서버에 요청해야 확인 가능 | 토큰만으로 검증 가능 |
| 예제 | 신용카드(승인 필요) | 영화관 표(바로 사용 가능) |

🔹 **유저 구분과 권한 부여 (RBAC - Role-Based Access Control)**  
- 직장에서의 역할과 비슷합니다.
- 예를 들어, 회사에서는 사장은 중요한 문서를 볼 수 있지만, 인턴은 볼 수 없습니다.
  마찬가지로, 웹사이트에서도 관리자는 모든 기능을 사용할 수 있지만, 일반 사용자는 일부 기능만 사용 가능하도록 설정하는 것

🔹 **비밀번호 해싱 (BCrypt)**  
- Spring Security는 비밀번호를 안전하게 저장하기 위해 `BCryptPasswordEncoder`를 제공  
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```
---

### 🔹 공개키 및 개인키 상세 설명

### 2.1 대칭 키와 비대칭 키
- **대칭 키(Symmetric Key)**: 하나의 키로 암호화와 복호화 수행 (예: HMAC)
- **비대칭 키(Asymmetric Key)**: 공개키(Public Key)와 개인키(Private Key)로 구성됨 (예: RSA, ECDSA)

#### 2.2 비대칭 키 개념
- **공개키(Public Key)**: 누구나 볼 수 있으며, 데이터를 암호화할 때 사용
- **개인키(Private Key)**: 소유자만이 보유하며, 암호화된 데이터를 복호화할 때 사용

#### 2.3 비대칭 암호화 적용 예시
- JWT 서명: 개인키로 서명, 공개키로 검증
- HTTPS (SSL/TLS): 클라이언트-서버 간 보안 연결을 제공
- SSH 키 인증: 비밀번호 없이 서버 접근을 가능하게 함

---

### 🔹 CSRF/XSRF (Cross-Site Request Forgery) (크로스 사이트 요청 위조)
**악성 웹사이트가 사용자의 계정을 몰래 이용하는 공격**

- CSRF 공격 방지를 위해 Spring Security는 기본적으로 CSRF 보호 기능을 활성화  
- REST API에서는 CSRF 보호를 **비활성화**하는 경우가 많음  

✔️ **비유**: "자동 이체 사기"
1. 사용자가 인터넷 뱅킹에 로그인한 상태에서 악성 광고를 클릭
2. 해커가 사용자의 계정에서 자동 송금

✔️ **방어 방법**:
java
http.csrf().enable();

---

### 🔹 CORS (교차 출처 리소스 공유)
**다른 출처에서 API 호출을 허용하는 방법**
- `@CrossOrigin` 애너테이션을 사용하여 설정 가능
- 
✔️ **비유**: "햄버거 가게 주문 규칙"
- A 햄버거 가게는 자사 배달 앱에서만 주문 가능 (기본 설정)
- B 배달 앱에서 주문하려면 **CORS 허용 필요**

✔️ **설정 방법**:
java
@CrossOrigin(origins = "https://example.com")

---

### 🔹 XSS (크로스 사이트 스크립팅)
**웹사이트에 악성 스크립트를 삽입하여 사용자 정보를 훔치는 공격**
- HTML 태그 삽입 공격을 방어하기 위해 input 값에 대한 검증 필요  
- Spring Security에서 기본적으로 XSS 방어 기능 제공
- 
✔️ **비유**: "악성 댓글 사기"
1. "이 링크 클릭하면 공짜 쿠폰!" 댓글 작성
2. 사용자가 클릭하면 해커에게 계정 정보 유출

✔️ **방어 방법**:
java
http.headers().xssProtection();

---
### 🔹 **인증(Authentication)과 인가(Authorization)란?**  
- **인증(Authentication)**: 사용자가 누구인지 확인하는 과정  
  - 예: 회사 출입문에서 직원 카드를 태그하면 "이 사람이 직원인가?"를 확인하는 것  
- **인가(Authorization)**: 인증된 사용자가 특정 기능을 사용할 수 있는지 결정하는 과정  
  - 예: 직원 카드를 태그해도 **사장실에는 접근할 수 없는 것처럼**, 사용자의 권한을 제한하는 것  

---

### 🔹 **Stateless(상태 없음) 방식이란?**  
- **서버가 사용자의 정보를 기억하지 않는 방식**  
- 예: **카페에서 주문할 때마다 신분증을 보여줘야 하는 시스템**  
- 서버가 고객 정보를 기억하지 않아서, **매번 로그인할 때 사용자 정보를 다시 보내야 함**  

---

## 🔐 보안에서 인증에 이용되는 토큰 정리

보안에서 **토큰(Token)** 은 사용자의 인증 및 권한 부여에 사용되는 문자열 또는 데이터 구조입니다. 토큰을 이용하면 서버는 사용자의 신원을 지속적으로 확인하지 않고도 인증 상태를 유지할 수 있습니다.

---

## 📌 1. 토큰의 역할
- 사용자의 **인증(Authentication)** 을 유지
- **권한 부여(Authorization)** 를 통해 리소스 접근 제어
- 세션을 저장하지 않고도 **무상태(Stateless) 인증** 가능
- 쿠키 기반 인증의 단점을 보완하고, 확장성이 뛰어남

---

## 📌 2. 토큰의 종류
### 1️⃣ **세션 토큰 (Session Token)**
- **개념**: 로그인 시 서버가 생성하여 클라이언트에 전달하는 토큰
- **저장 위치**: 서버의 세션 저장소 (DB, Redis 등)
- **특징**:
  - 서버에서 세션을 저장하고 관리해야 함 (Stateful)
  - 보안이 강하지만 서버 부하 증가 가능
  - 주로 **전통적인 웹 애플리케이션**에서 사용

---

### 2️⃣ **JWT (JSON Web Token)**
- **개념**: 인증 정보를 JSON 형태로 인코딩하여 서명한 토큰
- **구조**: `Header.Payload.Signature`
- **저장 위치**: 클라이언트 측 (로컬 스토리지, 쿠키, 세션 스토리지)
- **특징**:
  - **서버에서 상태를 저장할 필요 없음 (Stateless)**
  - 서명(Signature)으로 무결성 보장 (변조 감지 가능)
  - 짧은 만료 시간 설정이 필수 (탈취 시 보안 위험)
  - 자주 **OAuth 2.0, OpenID Connect, API 인증**에 사용됨
- **예제**:
  ```json
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
  eyJ1c2VySWQiOiIxMjM0NTYiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE2ODI2NjUyMDB9.
  dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
  ```

---

### 3️⃣ **OAuth 액세스 토큰 (Access Token)**
- **개념**: OAuth 2.0에서 사용자의 인증 후 API 접근을 위한 토큰
- **저장 위치**: 클라이언트 (메모리, 로컬 스토리지 등)
- **특징**:
  - API 요청 시 포함하여 리소스에 접근 가능
  - **만료 시간**이 짧음 (보통 몇 분~몇 시간)
  - OAuth 2.0 인증 흐름에서 사용됨 (예: Google, Facebook 로그인)
- **예제 (HTTP Authorization 헤더에 사용)**:
  ```http
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  ```

---

### 4️⃣ **OAuth 리프레시 토큰 (Refresh Token)**
- **개념**: 액세스 토큰이 만료되었을 때, 새 액세스 토큰을 받기 위한 토큰
- **저장 위치**: **보안이 강화된 저장소** (DB, Secure Storage)
- **특징**:
  - 액세스 토큰보다 **수명이 길다**
  - 탈취될 경우 보안 위험이 크므로 **안전한 저장** 필요
  - 일반적으로 **백엔드에서 관리**하며, 주로 **쿠키(httpOnly)** 에 저장

---

## 📌 3. 토큰 사용 시 보안 고려사항
✅ **토큰 저장 위치**  
- 액세스 토큰: **메모리** 또는 **httpOnly 쿠키**
- 리프레시 토큰: **보안 저장소** (DB, Secure Storage)

✅ **토큰 유효 기간 관리**  
- 액세스 토큰: **짧게 (5~30분)**
- 리프레시 토큰: **길게 (7일~30일)**
- 세션 토큰: **로그아웃 시 삭제**

✅ **HTTPS 사용**  
- 네트워크에서 **토큰 탈취 방지** (중간자 공격 방어)

✅ **서명 검증**  
- JWT는 서명을 검증하여 변조 여부 확인

✅ **토큰 탈취 시 대응 방법**  
- **단일 기기 세션 유지** (1개 이상의 로그인 방지)
- **로그아웃 시 리프레시 토큰 폐기**
- **IP, User-Agent 등 추가 확인**

---

## 📌 4. 토큰 비교 요약

| 토큰 종류       | 저장 위치 | 특징 | 주 사용처 |
|---------------|---------|-----|--------|
| **세션 토큰** | 서버 (DB, Redis) | 상태 유지 필요 | 전통적인 웹 인증 |
| **JWT** | 클라이언트 | 상태 저장 불필요, 서명 포함 | OAuth, OpenID, API 인증 |
| **OAuth 액세스 토큰** | 클라이언트 | API 접근 인증 | OAuth 2.0, 외부 서비스 |
| **OAuth 리프레시 토큰** | 서버 (DB) | 새 액세스 토큰 발급 | OAuth 장기 인증 |

---

## ✅ 결론
- **웹 애플리케이션**: JWT or 세션 토큰
- **OAuth 2.0 기반 API**: 액세스 토큰 + 리프레시 토큰
- **보안 강화 필요**: httpOnly 쿠키, HTTPS, 짧은 유효 기간 설정

-------

## 🔑 인증 및 인가 흐름

### 🔐 **인증 방식 요약**

| 인증 방식        | 설명 | 특징 | 주 사용처 |
|---------------|-----|-----|--------|
| **Spring Security** | Spring 기반의 보안 프레임워크 | 인증, 인가 처리 제공 | Spring 기반 웹 애플리케이션 |
| **OAuth 2.0** | 토큰 기반 인증 방식 | 액세스 토큰 & 리프레시 토큰 사용 | 소셜 로그인, API 인증 |
| **JWT (JSON Web Token)** | 무상태 인증 토큰 | 자체 서명 포함, 서버 상태 저장 불필요 | REST API, MSA 인증 |
| **Session 인증** | 서버 측에서 세션 저장 | 세션 ID를 쿠키로 저장, 서버 상태 유지 필요 | 전통적인 웹 애플리케이션 |

**📌 요약**
- **Spring Security**: 인증 및 인가를 처리하는 프레임워크  
- **OAuth 2.0**: 액세스 토큰을 이용한 인증 방식  
- **JWT**: 자체 서명이 포함된 토큰 기반 인증 (OAuth 2.0에서도 사용 가능)  
- **Session 인증**: 서버에 세션을 저장하는 방식 (Stateful)

각 방식은 **Spring Security에서 조합하여 사용 가능**하며, OAuth 2.0 및 JWT는 RESTful API 인증에 자주 활용됩니다! 🚀

### 1️⃣ **Spring Security만 사용한 경우**
1. 사용자가 로그인 요청 (ID/PW)
2. `UserDetailsService`가 사용자 정보 조회
3. `AuthenticationManager`가 인증 수행
4. 인증 성공 시 `SecurityContextHolder`에 사용자 정보 저장
5. 인증된 사용자가 보호된 리소스 요청 시 접근 허용

### 2️⃣ **JWT만 사용한 경우**
1. 사용자가 로그인 요청 (ID/PW)
2. 서버가 사용자 인증 후 JWT 생성 및 반환
3. 클라이언트가 요청 시 JWT를 `Authorization` 헤더에 포함
4. 서버는 JWT 서명을 검증 후 요청 처리

### 3️⃣ **Spring Security + JWT 사용한 경우**
1. 사용자가 로그인 요청 (ID/PW)
2. Spring Security가 사용자 인증 수행 후 JWT 발급
3. 클라이언트가 JWT를 포함하여 API 요청
4. Spring Security의 `JwtFilter`가 요청을 가로채서 JWT 검증
5. 검증된 경우 `SecurityContextHolder`에 사용자 정보 저장 후 요청 처리

---


## 📌 참고 및 출처
- 📖 [Modern API Development with Spring 6 and Spring Boot 3](https://github.com/PacktPublishing/Modern-API-Development-with-Spring-6-and-Spring-Boot-3)  
- 🔗 [SecurityFilterChain 종류 및 설명](https://docs.spring.io/spring-security/reference/servlet/architecture.html#servlet-security-filters)  
