# 🌐 Spring Security & JWT 정리

🚀 **Spring Security & JWT 학습을 위한 체계적인 정리 문서**!

## 🗂️ 목차
0. [**요약 정리**](#-요약-정리)
1. [**Spring Security 개요**](#-1-spring-security-개요)  
2. [**Spring Security 인증 과정**](#-2-spring-security-인증-과정)  
3. [**쿠키 vs 세션 vs JWT 인증**](#-3-쿠키cookie)  
4. [**세션(Session) 기반 인증**](#-4-세션session-기반-인증)  
5. [**토큰 기반 인증**](#5-토큰-기반-인증)  
6. [**JWT (JSON Web Token)**](#6-jwt-json-web-token)  
7. [**OAuth 2.0**](#7-oauth-20)  
8. [**보안 강화 및 권한 부여**](#-8-보안-강화-및-권한-부여)  
9. [**용어 정리**](#9-용어-정리)  
10. [**참고 및 출처**](#10--참고-및-출처)  
---


## 🎯 목적
이 문서는 **Spring Security와 JWT**를 학습하며 정리한 내용을 담고 있습니다.

---

## 🔔 요약 정리

### ✅ **쿠키 vs 세션 비교**
| 항목 | 쿠키 (Cookie) | 세션 (Session) |
|------|-------------|--------------|
| **저장 위치** | 클라이언트 (브라우저) | 서버 |
| **보안성** | 취약 (쿠키 탈취 가능, `httpOnly` 설정 필요) | 상대적으로 안전 (서버 관리) |
| **유효 기간** | 브라우저가 정한 시간 동안 유지 (`expires`, `max-age` 설정 가능) | 서버에서 관리, 일정 시간 동안 유지 (`session timeout`) |
| **인증 방식** | 요청마다 쿠키 포함하여 인증 (자동 전송) | 클라이언트가 `sessionId`를 포함하여 인증 |
| **서버 부담** | 없음 | 사용자가 많아질수록 서버 부담 증가 |
| **사용 예시** | 로그인 유지, 사용자 설정 저장 | 로그인 세션 관리, 인증된 사용자 정보 유지 |

---

### ✅ **토큰 인증 방식 비교 (JWT vs OAuth 2.0)**
| 항목 | JWT (JSON Web Token) | OAuth 2.0 |
|------|----------------------|-----------|
| **주요 목적** | API 인증, 사용자 인증 (토큰 기반 인증) | API 접근 제어 및 인증 연동 (3rd-party 인증) |
| **저장 위치** | 클라이언트 (로컬 스토리지, httpOnly 쿠키) | 인증 서버에서 관리 (불투명 토큰) |
| **유효 기간** | **짧음** (보안상 단기간 유지) | **액세스 토큰: 짧음**, 리프레시 토큰: 상대적으로 김 |
| **검증 방식** | 자체 검증 가능 (`Signature` 확인) | 인증 서버를 통해 토큰 검증 필요 |
| **사용 예시** | API 인증, 마이크로서비스 인증 | Google, Facebook 로그인, OAuth 기반 API 인증 |
| **보안 고려사항** | 토큰 탈취 시 위험 (짧은 만료시간 설정 필요) | 액세스 토큰 관리, 리프레시 토큰 보안 강화 필요 |

---

### ✅ **세션 vs JWT 비교**
| 항목 | 세션 기반 인증 | JWT 기반 인증 |
|------|--------------|--------------|
| **저장 위치** | 서버 (세션 저장소) | 클라이언트 (JWT 저장) |
| **확장성** | 낮음 (서버 메모리 사용 증가) | 높음 (Stateless, 서버 부담 없음) |
| **인증 방식** | `sessionId`를 쿠키에 저장 후 서버에서 검증 | `Authorization: Bearer <JWT>` 헤더 포함하여 인증 |
| **토큰 무효화** | 서버에서 세션 삭제 가능 | 불가능 (짧은 만료시간 + 리프레시 토큰 사용 필요) |
| **보안성** | 상대적으로 안전 (서버에서 관리) | 토큰 탈취 시 재사용 위험 (httpOnly 쿠키로 보호 가능) |
| **사용 예시** | 전통적인 웹 애플리케이션 | REST API, 마이크로서비스 |

---

### ✅ **전체적인 요약**
1. **Spring Security는 인증(Authentication)과 인가(Authorization)을 담당하는 강력한 보안 프레임워크**로, 여러 필터를 통해 요청을 검증함.
2. **기존의 세션 기반 인증**은 서버에서 세션을 관리하는 방식으로 보안성이 높지만 **확장성이 떨어지는 단점**이 있음.
3. **JWT 기반 인증**은 클라이언트가 토큰을 직접 관리하며, 서버 부담을 줄일 수 있지만, 토큰 탈취 시 보안 위험이 존재함.
4. **OAuth 2.0은 API 인증 및 외부 서비스 연동을 위해 사용되며, 액세스 토큰과 리프레시 토큰을 활용하여 인증을 관리**함.
5. **보안 강화를 위해 CSRF, XSS 방어, CORS 설정, 비밀번호 해싱(BCrypt) 등을 적용하여 보안성을 높여야 함**.

-------

## 📌 1. Spring Security 개요

### ✅**1.1 Spring Security란?**
Spring 기반 애플리케이션의 **인증(Authentication)** 과 **인가(Authorization)** 를 관리하는 보안 프레임워크입니다.  
🔖 [_Boilerplate Code_](#-boilerplatecode)를 직접 작성하지 않고도 **표준화된 보안 기능(인증, 인가, 세션 관리, CSRF 보호 등)을 손쉽게 구현할 수 있도록 지원하는 라이브러리 기반 프레임워크**입니다.  

➡ **즉, 보안 관련 로직을 직접 구현할 필요 없이, Spring Security가 제공하는 기능을 활용하여 안전한 애플리케이션을 개발할 수 있습니다.**  

### **주요 기능:**
- ✅ **인증(Authentication)**: 사용자가 누구인지 확인
- ✅ **인가(Authorization)**: 사용자의 접근 권한 결정
- ✅ **보안 필터(Security Filters)**: 요청 및 응답에 대한 보안 검사 수행
- ✅ **비밀번호 암호화(BCrypt)**: 안전한 비밀번호 저장
- ✅ **CSRF/XSRF 보호**: CSRF 공격 방지

**Spring Security의 라이브러리 및 Gradle 설정**
   - 내용 입력하기

### ✅1.2 Spring Security 요청 처리 흐름

1. 클라이언트 요청 → `DispatcherServlet` → `Security Filter` → 컨트롤러 → 서비스 → DB
2. 사용자가 로그인 정보를 입력 → 보안 시스템(Spring Security)이 이를 확인 → 로그인 성공 후 사용자 정보 조회 → 접근 권한 결정
3. `SecurityFilterChain`이 요청을 가로채어 인증 및 인가 수행

**SecurityFilterChain의 역할:**
- **Pre-filter**: 요청이 컨트롤러로 전달되기 전에 적용, 보안 검사를 수행하는 필터
- **Post-filter**: 컨트롤러에서 응답이 반환되기 전에 보안 정책을 적용하는 필터.


---


## 📌 2. Spring Security 인증 과정

Spring Security는 여러 개의 **필터 체인(Filter Chain)**을 통해 보안 기능을 제공합니다.

### ✅2.1 기본적인 인증 과정
1. **사용자가 로그인 요청을 보냄**
   - 로그인 폼 제출 → `HttpServletRequest`를 통해 사용자 정보(ID, PW) 전달

2. **`UsernamePasswordAuthenticationFilter`가 요청을 가로챔**
   - `UsernamePasswordAuthenticationToken` 객체로 변환
   - `ProviderManager`에게 인증 요청 전달

3. **`AuthenticationProvider`가 인증 처리**
   - `ProviderManager`가 적절한 `AuthenticationProvider`를 찾아 인증 요청을 전달
   - `UserDetailsService`를 통해 DB에서 사용자 정보 조회
   - `PasswordEncoder`(BCrypt)로 비밀번호 검증
   - 인증 성공 시 `Authentication` 객체 반환

4. **SecurityContext에 Authentication 저장**
   - `SecurityContextHolder`에 인증된 사용자 정보 저장 → 이후 요청에서 인증 상태 유지

### ✅2.2 Spring Security 필터 체인 구조
**Spring Security는 여러 개의 필터를 통해 보안 기능을 적용합니다.**

 No  | 필터명 | 역할 |
|-----|----------------------------------|-------------------------------------------------|
| 1   | `SecurityContextPersistenceFilter` | SecurityContext 객체를 생성, 저장, 조회 (요청 시작 시 복원, 응답 시 저장) |
| 2   | `UsernamePasswordAuthenticationFilter` | ID/PW 기반 로그인 요청을 처리하여 AuthenticationManager에 인증 요청 |
| 3   | `BasicAuthenticationFilter` | HTTP Basic 인증 방식 처리 (Authorization: Basic {credentials}) |
| 4   | `BearerTokenAuthenticationFilter` | Authorization: Bearer {token} 헤더를 통한 JWT 및 OAuth2 토큰 인증 |
| 5   | `ExceptionTranslationFilter` | 인증 및 권한 관련 예외 (AccessDeniedException, AuthenticationException) 처리 |
| 6   | `FilterSecurityInterceptor` | 인증된 사용자의 접근 권한을 검사 (AccessDecisionManager와 함께 동작) |
| 7 |  `OAuth2LoginAuthenticationFilter` | OAuth2 로그인 처리 |

<br>

---

<br>

### ✅2.3 인증 방식에 따른 Spring Security 필터 체인 구조의 변화

#### **✅1. 기존 폼 로그인 (Session 기반 인증)**
- 사용자가 **ID/PW**를 입력하여 로그인하면, `UsernamePasswordAuthenticationFilter`가 작동.
- 인증이 성공하면 **세션(Session)에 Authentication 정보**를 저장하여 관리.

**필터 체인 흐름**
```
1. SecurityContextPersistenceFilter (SecurityContext 관리)
2. UsernamePasswordAuthenticationFilter (폼 로그인 처리)
3. DefaultLoginPageGeneratingFilter (기본 로그인 페이지 제공 - 필요 시)
4. BasicAuthenticationFilter (Basic Auth 지원)
5. RequestCacheAwareFilter (요청 캐시 처리)
6. SecurityContextHolderFilter (SecurityContext 설정)
7. AuthorizationFilter (인가 처리)
```

---

#### **✅2. OAuth2.0 로그인 (OAuth2.0 기반 인증)**
- 사용자가 **OAuth2.0 Provider(Google, Kakao 등)**를 통해 로그인하면, `OAuth2LoginAuthenticationFilter`가 작동.
- OAuth2 로그인 후, **SecurityContext에 Authentication 객체를 저장**하여 관리.

**필터 체인 흐름**
```
1. SecurityContextPersistenceFilter
2. OAuth2LoginAuthenticationFilter (OAuth2.0 인증 처리)
3. RequestCacheAwareFilter
4. SecurityContextHolderFilter
5. AuthorizationFilter
```

---

#### **✅3. JWT 기반 인증**
- **Stateless 방식**이므로 **세션을 사용하지 않음**.
- 로그인 시, `UsernamePasswordAuthenticationFilter`에서 **JWT를 생성하여 응답**.
- 이후 요청 시, `JwtAuthenticationFilter`(커스텀 필터)가 동작하여 **JWT를 검증 및 인증 처리**.

**필터 체인 흐름**
```
1. SecurityContextPersistenceFilter
2. JwtAuthenticationFilter (JWT 검증 및 SecurityContext 설정)
3. RequestCacheAwareFilter
4. SecurityContextHolderFilter
5. AuthorizationFilter
```

🔹 **핵심 차이점**
- **기존 폼 로그인 → `UsernamePasswordAuthenticationFilter`**
- **OAuth2.0 로그인 → `OAuth2LoginAuthenticationFilter`**
- **JWT 인증 → 커스텀 필터 (`JwtAuthenticationFilter`) 추가하여 인증 처리**

---

#### **✅ JWT를 적용할 때의 주요 변경 사항**
1. **세션을 사용하지 않으므로, SecurityContextPersistenceFilter 설정 변경**
   ```java
   httpSecurity
       .sessionManagement(session -> session
           .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용 안함
       )
   ```
   
2. **JWT 인증을 위한 필터 추가 (`JwtAuthenticationFilter`)**
   ```java
   httpSecurity
       .addFilterBefore(new JwtAuthenticationFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class);
   ```

3. **기본 로그인 방식 제거**
   ```java
   httpSecurity
       .formLogin(AbstractHttpConfigurer::disable)
       .httpBasic(AbstractHttpConfigurer::disable);
   ```

---

### ✅ **정리**
| 인증 방식  | 주요 필터 | 필터 목적 |
|------------|------------------------------|----------------------|
| **폼 로그인** | `UsernamePasswordAuthenticationFilter` | ID/PW 인증 및 세션 저장 |
| **OAuth2.0 로그인** | `OAuth2LoginAuthenticationFilter` | 소셜 로그인 처리 |
| **JWT 인증** | `JwtAuthenticationFilter` (커스텀) | JWT 검증 및 인증 |

✔️ **JWT 사용 시에는 UsernamePasswordAuthenticationFilter를 그대로 사용하여 JWT 발급 후, 이후 요청에서 JwtAuthenticationFilter를 통해 JWT 검증을 수행**하는 방식으로 변경됨.

---

## **📌 3. 쿠키(Cookie)**
쿠키는 **사용자의 인증 정보를 브라우저에 저장하여 로그인 상태를 유지하는 방식**입니다.

---

### **✅ 3.1 쿠키(Cookie)란?**
- 클라이언트(브라우저)에 저장되는 **작은 데이터 조각**  
- 서버가 클라이언트에 응답할 때 **Set-Cookie** 헤더를 통해 생성  
- 이후 요청마다 **쿠키를 자동으로 포함하여 서버에 전송**  
- **주로 세션 ID나 JWT를 저장하는 용도로 사용됨**  

---

### **✅ 3.2 쿠키의 특징**
✅ **자동 전송:** 브라우저가 요청마다 자동으로 쿠키를 서버에 전송  
✅ **도메인 기반:** 특정 도메인에서만 사용 가능 (`SameSite` 정책으로 보안 강화 가능)  
✅ **httpOnly 옵션:** XSS 공격 방지를 위해 **JavaScript에서 접근 불가능하도록 설정 가능**  
✅ **보안 설정:** `Secure` 속성을 설정하면 **HTTPS에서만 쿠키 전송 가능**  

---

### **✅ 3.3 쿠키의 예제 (Set-Cookie 헤더)**
```http
Set-Cookie: sessionId=abc123; HttpOnly; Secure; SameSite=Strict
```
- **sessionId=abc123** → 세션 ID 저장  
- **HttpOnly** → JavaScript에서 접근 불가능 (XSS 방어)  
- **Secure** → HTTPS에서만 쿠키 전송  
- **SameSite=Strict** → CSRF 공격 방지 (타 사이트 요청에서 쿠키 자동 전송 차단)  

---

### **✅ 3.4 쿠키 기반 인증의 흐름**
1️⃣ 사용자가 로그인 요청 (`/login`)  
2️⃣ 서버가 **사용자를 인증 후 쿠키를 생성**하여 응답  
3️⃣ 클라이언트(브라우저)가 쿠키를 저장  
4️⃣ 이후 요청마다 **쿠키를 포함하여 서버에 자동 전송**  
5️⃣ 서버가 쿠키를 확인하고 사용자 인증 수행  

---

## **📌 4. 세션(Session) 기반 인증**
세션(Session)은 **사용자의 로그인 정보를 서버에서 관리하는 방식**입니다.

---

### **✅ 4.1 세션(Session)이란?**
- 서버가 **사용자의 로그인 상태를 유지하기 위해 생성하는 데이터**  
- 클라이언트는 `sessionId` 쿠키를 이용하여 세션을 식별  
- **세션 정보는 서버에서 관리되며, 클라이언트에는 세션 ID만 저장**  
- 보통 **Redis, DB, In-Memory Store(예: HttpSession)** 등을 이용해 저장  

---

### **✅ 4.2 세션의 특징**
✅ **서버에서 사용자 상태를 관리** → 무결성이 높음  
✅ **쿠키에는 sessionId만 저장** → 보안성이 더 높음  
✅ **클라이언트가 쿠키를 삭제해도 서버에서 로그아웃 처리 가능**  
✅ **세션 기반 인증의 서버 부하 증가 원인**
- 서버가 **각 사용자의 세션을 유지**해야 하기 때문에, 사용자가 많아질수록 메모리 사용량이 증가함.
- 여러 서버(멀티 노드)에서 동작하는 경우, **세션 정보를 공유하는 문제** 발생 (예: Redis, DB 활용 필요).
- 따라서 **확장성(Scalability)**이 필요한 서비스에서는 세션 기반 인증보다는 JWT 기반 인증이 선호됨.
 

---

### **✅ 4.3 세션 기반 인증의 흐름**
1️⃣ 사용자가 로그인 요청 (`/login`)  
2️⃣ 서버가 **사용자를 인증 후 세션 생성 (sessionId 발급)**  
3️⃣ **sessionId를 쿠키에 담아 클라이언트에 전달**  
4️⃣ 클라이언트는 이후 요청마다 **sessionId 쿠키를 자동으로 포함**  
5️⃣ 서버는 **sessionId를 확인하여 로그인 상태 유지**  

---

### **✅ 4.4 세션과 쿠키의 관계**
- **쿠키는 클라이언트 측에서 세션 ID를 저장하는 용도로 사용됨**  
- 서버에서 세션을 생성하면 **sessionId가 쿠키에 저장**됨  
- 이후 요청마다 **sessionId가 자동 전송**되어 사용자를 인증함  

---


## **📌5. 토큰 기반 인증**  

### **✅ 토큰 기반 인증이란?**  
- **서버가 사용자의 인증 상태를 유지하는 방법 중 하나**  
- 기존 **세션 기반 인증과 달리, 서버가 상태(세션)를 유지할 필요 없음 (Stateless)**  
- 일반적으로 **JWT (JSON Web Token) 방식이 가장 많이 사용됨**  
- **OAuth 2.0, OpenID Connect, API 인증 등에 널리 활용됨**  

### **✅ 토큰 기반 인증의 특징**  
| 항목 | 설명 |
|------|------|
| **서버 부담** | 서버가 세션을 저장하지 않으므로 **확장성이 뛰어남** |
| **보안성** | **서명(Signature) 검증을 통해 변조 방지** 가능 |
| **단점** | 토큰 탈취 시 보안 위협 (짧은 만료 시간 설정 필수) |

---

### **✅ 토큰 기반 인증의 유형**
- **JWT (JSON Web Token):** 클라이언트에서 직접 저장, 검증 가능 (Stateless). 가장 많이 사용되는 방식
- **Opaque Token (불투명 토큰):** 서버에서 관리되며, 클라이언트가 내용을 알 수 없음 (OAuth 2.0 기본 방식).
- **OAuth2.0 액세스 토큰:** API 접근 권한 부여 (보통 불투명 토큰 사용).
- **OAuth 2.0 리프레시 토큰** → 새 액세스 토큰 발급  
- **API Key 방식:** 간단한 API 인증 방식이지만 보안 취약.


---

## **📌6. JWT (JSON Web Token)**

### ✅**6.1 JWT 개요**
JWT는 **토큰 기반 인증 방식**으로, 로그인 후 발급된 JWT를 사용하여 인증을 수행하는 **Stateless 인증 방식**입니다.
클라이언트가 로그인하면 JWT를 발급받고 이후 요청마다 JWT를 포함하여 인증 수행합니다.

### ✅**6.2 JWT의 구성**
| 구성 요소 | 설명 | 예제 |
|--------|------|------|
| **헤더 (Header)** | 토큰의 유형 정보와 서명 알고리즘 암호화 방식 | JWT, HS256 |
| **페이로드 (Payload)** | 사용자 정보 (ID, 권한 등), 클레임 포함 | { "user": "John", "role": "admin" } |
| **서명 (Signature)** | 위변조 방지 서명 (무결성 보장) | 암호화된 해시값 |

#### 페이로드의 클레임(Claims) 정의 및 종류
클레임(Claims)은 토큰에 포함된 데이터로 등록된 클레임, 공개 클레임, 비공개 클레임으로 나뉘어짐

1) **등록된 클레임(Registered Claims)**
JWT 표준에 정의된 클레임으로, 사용이 권장됨.
- iss (Issuer) - 발급자
- sub (Subject) - 토큰의 주제 (사용자 ID 등)
- aud (Audience) - 토큰을 사용할 대상
- exp (Expiration) - 만료 시간
- nbf (Not Before) - 특정 시간 이전에는 토큰이 유효하지 않음
- iat (Issued At) - 토큰이 발급된 시간
- jti (JWT ID) - 토큰의 고유 식별자

2) **공개 클레임(Public Claims)**
사용자가 정의한 클레임으로, 충돌을 방지하기 위해 공식적으로 등록된 네임스페이스 사용 권장. <br>
예: https://myapp.com/user_role

3) **비공개 클레임(Private Claims)**
특정 애플리케이션이나 시스템 내부에서만 사용되는 클레임. <br>
예: { "user_id": "12345", "role": "admin" }

---


### ✅**6.3 JWT 인증 과정**
1. **사용자가 로그인 요청** → 서버에서 JWT 생성 및 반환
2. **클라이언트가 API 요청 시 JWT를 `Authorization` 헤더에 포함**
3. **서버는 JWT 서명 검증 후 요청 처리**
4. **(RSA 사용 시)** 개인키로 서명한 JWT를 공개키로 검증하여 신뢰성 보장  


### ✅**6.4 JWT 서명 및 암호화 방식 (HMAC vs RSA)**
JWT의 서명 검증 방식은 **대칭 키(HMAC)와 비대칭 키(RSA, ECDSA)** 방식으로 구분됨.  

#### 🔹 **대칭 키(Symmetric Key)**
- 하나의 키를 사용하여 암호화와 복호화를 수행.  
- **예시:** HMAC (Hash-based Message Authentication Code)  
- **특징:**  
  - 빠르고 간단한 구조  
  - 키가 유출되면 보안에 취약  

#### 🔹 **비대칭 키(Asymmetric Key)**
- **공개키(Public Key):** 누구나 볼 수 있으며, 데이터를 암호화할 때 사용.  
- **개인키(Private Key):** 소유자만이 보유하며, 암호화된 데이터를 복호화할 때 사용.  

#### 🔹 **비대칭 암호화 적용 예시**
- **JWT 서명:** 개인키로 서명, 공개키로 검증 (예: RSA, ECDSA)

   - **RSA의 원리:**  
  - 송신자는 **개인키(Private Key)**로 데이터를 서명  
  - 수신자는 **공개키(Public Key)**로 서명을 검증  
  - 이를 통해 데이터의 무결성과 발신자를 신뢰할 수 있음 

   - **ECDSA:**  
  - 타원 곡선 암호학(ECC)을 기반으로 한 서명 알고리즘  
  - **RSA보다 짧은 서명 크기로도 동일한 보안 수준 제공**  
  - **IoT, 블록체인 등 성능이 중요한 환경에서 사용됨**  

---


### ✅**6.5 JWT vs 세션 기반 인증 비교**
| 비교 항목 | JWT | 세션 기반 인증 |
|----------|-----|---------------|
| 저장 방식 | 클라이언트 (토큰 저장) | 서버 측 (세션 저장) |
| 확장성 | 높음 (Stateless) | 낮음 (서버 부하 증가) |
| 보안성 | 토큰 탈취 시 위험, 그러나 서명을 포함하면 변조를 방지할 수 있음 | 세션 하이재킹 위험 |

### ✅**6.6 불투명 토큰(Opaque Token) vs JWT**
| 비교 항목 | 불투명 토큰 (Opaque Token) | JWT |
|----------|-----------------|------|
| 저장 방식 | 서버에서 관리 | 클라이언트에서 관리 |
| 검증 방식 | 서버에 요청해야 확인 가능 | 토큰만으로 검증 가능 (자체적으로 검증 가능 (서명 포함)) |
|실사용 예제 |	OAuth2.0 액세스 토큰 |	API 인증, 마이크로서비스 |
| 예제 | 신용카드(승인 필요) | 영화관 표(바로 사용 가능) |

---

### ✅**6.7 JWT 보안 취약점 및 해결 방법**
1. **토큰 탈취 위험**  
   - JWT는 클라이언트에서 저장되므로 탈취되면 재사용될 위험이 있음.
   - 해결책: **JWT를 httpOnly 쿠키에 저장**하여 JavaScript에서 접근 불가능하게 설정.

2. **토큰 무효화 어려움**  
   - 세션 기반 인증과 달리 JWT는 서버에서 즉시 폐기하기 어려움.
   - 해결책: **짧은 만료 시간(exp) 설정 + 리프레시 토큰 사용**.

3. **서명 키(Secret Key) 유출 위험**  
   - HMAC 서명을 위한 키가 유출되면 공격자가 위조된 토큰을 생성 가능.
   - 해결책: **서버 환경 변수로 관리하고, 정기적으로 키를 변경**.

4. **과도한 페이로드(클레임) 포함**  
   - JWT에 너무 많은 정보를 담으면 **토큰 크기가 커지고 전송 비용 증가**.
   - 해결책: **필요한 최소한의 정보만 포함**.


## **📌7. OAuth 2.0**

### **✅ 7.1 OAuth 2.0 개요**
OAuth 2.0은 **사용자 인증 및 API 접근을 안전하게 처리하기 위한 표준 프로토콜**입니다.
JWT와 불투명 토큰을 모두 사용할 수 있으며, **외부 서비스**(Google, Facebook, GitHub 등)와의 **인증 연동**에 주로 사용됩니다.

### **✅ 7.2 OAuth 2.0의 핵심 개념**  

**사용되는 대표적인 환경**
- **Spring Security** (Java)
- **Express.js + Passport.js** (Node.js)
- **Django OAuth Toolkit** (Python)

| 개념 | 설명 |
|------|------|
| **리소스 소유자 (Resource Owner)** | 서비스의 사용자 (예: 구글 계정 사용자) |
| **클라이언트 (Client)** | 사용자의 정보를 요청하는 애플리케이션 (예: GitHub, Facebook 앱) |
| **인증 서버 (Authorization Server)** | 사용자 인증 및 액세스 토큰 발급 (예: Google OAuth Server) |
| **리소스 서버 (Resource Server)** | 보호된 리소스를 제공하는 서버 (예: Google API, Facebook Graph API) |
| **액세스 토큰 (Access Token)** | API 요청 시 필요한 인증 토큰 (보통 불투명 토큰) |
| **리프레시 토큰 (Refresh Token)** | 액세스 토큰이 만료되었을 때 새로 발급받기 위한 토큰 |

✅ **OAuth 2.0의 핵심 원칙:**  
- **"ID/PW를 직접 공유하지 않고, 서비스 간 안전한 인증을 수행"**  
- **액세스 토큰을 이용하여 API 접근을 관리**  
- **토큰이 만료되면 리프레시 토큰을 사용하여 새로운 액세스 토큰을 발급받을 수 있음**  

---


### **✅ 7.3 OAuth 2.0에서 사용하는 토큰**  

#### **1️⃣ OAuth 액세스 토큰 (Access Token)**
- **역할:** API 요청을 인증하기 위한 토큰  
- **저장 위치:** 클라이언트 (메모리, 로컬 스토리지, httpOnly 쿠키 등)  
- **특징:**  
  - API 요청 시 `Authorization: Bearer <token>` 형태로 포함  
  - **만료 시간이 짧음 (보통 몇 분~몇 시간)**  
  - 보안 강화를 위해 **httpOnly 쿠키에 저장하거나, 매 요청마다 서버에서 검증하도록 설정**  
- **예제 (HTTP Authorization 헤더 사용)**:
  ```http
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  ```

---

#### **2️⃣ OAuth 리프레시 토큰 (Refresh Token)**
- **역할:** 액세스 토큰이 만료되었을 때, 새 액세스 토큰을 받기 위한 토큰  
- **저장 위치:** **보안이 강화된 저장소** (DB, Secure Storage, httpOnly 쿠키)  
- **특징:**  
  - **액세스 토큰보다 수명이 길다 (보통 몇 주~몇 개월)**  
  - **탈취될 경우 보안 위험이 크므로 안전한 저장이 필요**  
  - 일반적으로 **서버에서 관리**하며, **httpOnly 쿠키 또는 DB에 저장**  
- **예제 (리프레시 요청 시 사용)**:
  ```http
  POST /oauth/token
  Content-Type: application/x-www-form-urlencoded

  grant_type=refresh_token&refresh_token=xyz123
  ```

⁉️ **리프레시 토큰이 필요한 이유**
- 액세스 토큰은 보안을 위해 **짧은 만료 시간**을 갖도록 설정됨 (예: 15분 ~ 1시간).
- 사용자가 계속해서 서비스를 이용하려면, **새로운 액세스 토큰을 발급받아야 함**.
- 하지만 **매번 로그인하면 불편하기 때문에**, 리프레시 토큰을 이용하여 **자동으로 새로운 액세스 토큰을 발급**.
- **리프레시 토큰의 보안 위험**:
  - 탈취되면 장기간 사용 가능하기 때문에 **보안이 강화된 저장 방식(httpOnly 쿠키, Secure Storage)**이 필요함.
  - 리프레시 토큰이 유출되었을 경우, **블랙리스트에 추가하여 즉시 폐기 가능**.

---


### **✅ 7.4 OAuth 2.0 인증 흐름**
OAuth 2.0에는 다양한 인증 방식이 존재하지만, 가장 많이 사용되는 **Authorization Code Flow**를 기준으로 설명합니다.  

**🔹 Authorization Code Flow**  
1️⃣ **사용자가 클라이언트 앱에서 로그인 요청**  
2️⃣ **클라이언트가 인증 서버(예: Google OAuth)에 인증 요청**  
3️⃣ **사용자가 Google 로그인 후 "권한 부여" 승인**  
4️⃣ **인증 서버가 클라이언트에 "인가 코드" 발급**  
5️⃣ **클라이언트가 "인가 코드"를 이용하여 액세스 토큰 요청**  
6️⃣ **인증 서버가 클라이언트에 액세스 토큰 발급**  
7️⃣ **클라이언트가 액세스 토큰을 API 요청 시 포함하여 인증 수행**  
8️⃣ **액세스 토큰이 만료되면, 리프레시 토큰을 이용하여 새 액세스 토큰 요청**  

---

### **✅ 7.5 OAuth 2.0 인증 방식 (Authorization Grant Types)**
OAuth 2.0에는 다양한 **권한 부여 방식(Grant Types)** 이 있으며, 각각의 방식은 사용 목적이 다릅니다.

| 인증 방식 | 설명 | 사용 예제 |
|----------|------|----------|
| **Authorization Code (인가 코드 방식)** | **가장 안전한 방식**으로, 클라이언트가 직접 사용자 인증 정보를 처리하지 않음 | Google, Facebook 로그인 |
| **Implicit (암시적 방식, 비추천)** | 브라우저 기반 앱(SPA)에서 사용되었으나 보안 취약성으로 현재는 거의 사용되지 않음 | ❌ 비추천 |
| **Client Credentials (클라이언트 자격 증명 방식)** | 사용자 없이 클라이언트 자체가 API를 호출하는 경우 사용 | **마이크로서비스 간 통신** |
| **Password Grant (비밀번호 방식, 비추천)** | 사용자가 **ID/PW를 직접 제공하는 방식**으로, 보안성이 낮아 거의 사용되지 않음 | ❌ 비추천 |

⁉️ **왜 Implicit Grant와 Password Grant 방식이 비추천될까?**
- **Implicit Grant (암시적 인증 방식)**
  - 브라우저에서 직접 액세스 토큰을 받기 때문에 **토큰이 URL에 노출될 위험이 큼**.
  - 토큰이 쉽게 탈취될 수 있어 보안성이 낮음.
  - 현재 OAuth 2.1에서는 **권장되지 않는 방식**.

- **Password Grant (비밀번호 방식)**
  - 사용자의 **ID/PW를 직접 클라이언트에서 입력받아 서버로 보내야 함** → 보안 취약.
  - OAuth의 기본 원칙인 **"ID/PW를 공유하지 않고 인증"**하는 원칙과 반대됨.
  - 따라서, **대체 방식으로 Authorization Code Flow를 사용해야 함.**


---

### **✅ 7.6 OAuth 2.0에서 JWT와 불투명 토큰의 사용**
OAuth 2.0에서는 **JWT와 불투명 토큰을 모두 사용할 수 있음**.  
하지만, **어떤 환경에서 사용하는지에 따라 적합한 방식이 다름**.  

| 사용 사례 | JWT 사용 | 불투명 토큰 사용 |
|----------|---------|---------------|
| **마이크로서비스 환경 (MSA)** | ✅ 권장 | ❌ 비효율적 |
| **OAuth 2.0 API 인증** | ❌ 대부분 불투명 토큰 사용 | ✅ 권장 (액세스 토큰) |
| **서버 부하 최소화** | ✅ 토큰 자체 검증 가능 | ❌ 서버 요청 필요 |
| **토큰 폐기 및 관리 필요** | ❌ 어려움 (서버에서 관리 불가능) | ✅ 서버에서 중앙 관리 가능 |


⁉️ **JWT vs 불투명 토큰: 언제 사용할까?**
- **JWT를 사용하는 경우:**
  - 마이크로서비스 환경(MSA)에서 중앙 인증 서버 없이 자체적으로 토큰 검증이 필요할 때.
  - API 게이트웨이가 토큰 검증을 수행하고 개별 서비스에서 다시 검증할 필요가 없을 때.

- **불투명 토큰을 사용하는 경우:**
  - OAuth 2.0을 통해 API 인증을 수행할 때 (예: Google, Facebook API).
  - 보안성이 중요한 환경에서 토큰을 서버에서 관리하고 검증해야 할 때.
  - 액세스 토큰을 즉시 폐기해야 하는 경우 (JWT는 서버에서 폐기가 어렵지만, 불투명 토큰은 가능).


✅ **결론:**  
- **OAuth 2.0의 액세스 토큰은 불투명 토큰을 기본으로 사용**  
- **OAuth 2.0에서 JWT를 사용할 수도 있지만, 서버에서 직접 검증해야 하는 불투명 토큰이 기본적**  


## 📌 8. 보안 강화 및 권한 부여

### ✅8.1 RBAC (Role-Based Access Control)
**사용자의 역할(Role)에 따라 접근 권한을 설정하는 방식**

- 직장에서의 역할과 비슷합니다.
- 예를 들어, 회사에서는 사장은 중요한 문서를 볼 수 있지만, 인턴은 볼 수 없습니다.
  마찬가지로, 웹사이트에서도 관리자는 모든 기능을 사용할 수 있지만, 일반 사용자는 일부 기능만 사용 가능하도록 설정하는 것

- `@Secured("ROLE_ADMIN")` → 특정 역할을 가진 사용자만 접근 가능
- `@PreAuthorize("hasRole('USER')")` → 실행 전 권한 체크
- `@PostAuthorize("returnObject.owner == authentication.name")` → 실행 후 반환 값 검증

**RBAC의 장점과 한계**
✅ **장점:**
- 역할을 기반으로 권한을 관리하므로 **유지보수가 용이**함.
- 역할 단위로 사용자 그룹을 관리하여 **대규모 시스템에 적합**.
- 접근 권한을 역할에 할당하므로 **보안성이 향상**됨.

❌ **한계:**
- **역할(Role)이 너무 많아지면 관리가 복잡해질 수 있음** (예: 수십 개의 역할이 존재하는 경우).
- **세부적인 권한 설정에는 한계가 있음** → 이를 해결하기 위해 **ABAC(Attribute-Based Access Control)** 같은 방식이 필요할 수 있음.

---

### ✅8.2 비밀번호 해싱 (BCrypt)
- Spring Security는 비밀번호를 안전하게 저장하기 위해 `BCryptPasswordEncoder`를 제공  
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

⁉️ **왜 비밀번호 해싱이 필요한가?**
- 비밀번호를 평문(Plain Text)으로 저장하면 데이터베이스가 해킹당할 경우 **모든 사용자 정보가 유출됨**.
- 이를 방지하기 위해 해싱(Hashing)을 사용하여 **비밀번호를 복호화할 수 없도록 변환**.

**BCrypt의 특징**
- **Salt 자동 추가** → 같은 비밀번호라도 **매번 다른 해시 값이 생성됨**.
- **연산 비용 조정 가능** → 보안 수준을 높이기 위해 연산 비용을 설정할 수 있음.
- **Rainbow Table 공격 방어** → Salt 덕분에 Rainbow Table 공격(사전 해시 값 매칭 공격)이 어려움.




---

### ✅8.3 CSRF/XSRF
**악성 웹사이트가 사용자의 계정을 몰래 이용하는 공격**

- CSRF 공격 방지를 위해 Spring Security는 기본적으로 CSRF 보호 기능을 활성화  
- REST API에서는 CSRF 보호를 **비활성화**하는 경우가 많음  

✔️ **비유**: "자동 이체 사기"
1. 사용자가 인터넷 뱅킹에 로그인한 상태에서 악성 광고를 클릭
2. 해커가 사용자의 계정에서 자동 송금

✔️ **방어 방법**
```java
http.csrf().disable();
```

⁉️ **왜 REST API에서는 CSRF 보호를 비활성화할까?**
- CSRF 공격은 **브라우저의 쿠키 자동 전송**을 악용하는 공격.
- 하지만 REST API에서는 **주로 JWT 기반 인증(Authorization 헤더 사용)**을 사용하기 때문에 **쿠키 기반 인증이 아닌 경우 CSRF 위험이 낮음**.
- 즉, **클라이언트가 직접 Authorization 헤더를 추가해야 하므로, 불필요한 CSRF 보호를 비활성화하는 경우가 많음**.



---

### ✅8.4 CORS 설정 (Cross-Origin Resource Sharing)
**다른 출처에서 API 호출을 허용하는 방법**
- `@CrossOrigin` 애너테이션을 사용하여 설정 가능
- 
✔️ **비유**: "햄버거 가게 주문 규칙"
- A 햄버거 가게는 자사 배달 앱에서만 주문 가능 (기본 설정)
- B 배달 앱에서 주문하려면 **CORS 허용 필요**

✔️ **설정 방법**
```java
@CrossOrigin(origins = "https://example.com")
```

⁉️ **CORS에서 Preflight 요청이란?**
- 클라이언트가 서버에 실제 요청을 보내기 전에, **OPTIONS 요청을 보내서 허용된 메서드/헤더를 확인**하는 과정.
- 브라우저가 자동으로 실행하며, 보안 목적(서버가 요청을 허용하는지 확인)을 가짐.

⁉️ **CORS에서 Credentials 옵션이란?**
- 기본적으로 CORS 요청은 **쿠키를 포함하지 않음**.
- 하지만 `credentials: 'include'` 옵션을 추가하면, 쿠키와 인증 정보를 함께 전송할 수 있음.
- 서버에서도 `Access-Control-Allow-Credentials: true` 설정이 필요.


---

### ✅8.5 XSS (Cross-Site Scripting)
**웹사이트에 악성 스크립트를 삽입하여 사용자 정보를 훔치는 공격**
- HTML 태그 삽입 공격을 방어하기 위해 input 값에 대한 검증 필요  
- Spring Security에서 기본적으로 XSS 방어 기능 제공

✔️ **비유**: "악성 댓글 사기"
1. "이 링크 클릭하면 공짜 쿠폰!" 댓글 작성
2. 사용자가 클릭하면 해커에게 계정 정보 유출

✔️ **방어 방법**
```java
http.headers().xssProtection();
http.headers().contentSecurityPolicy("script-src 'self'");  
```

*    ✅ xssProtection() vs contentSecurityPolicy()

| 비교항목 | xssProtection() | contentSecurityPolicy() |
|-------|-------|-------|
|지원 여부 |   오래된 브라우저에서만 동작 (Chrome, Firefox 지원 X) |	모든 최신 브라우저에서 지원됨
|보안 강도 |	브라우저가 XSS 공격을 감지하면 차단 |	XSS 공격 자체를 차단 (스크립트 실행 금지)
|차단 방식 |	XSS 공격 감지 후 페이지 로드 차단 |	허용된 스크립트 외 실행 차단
|권장 여부 |	❌ 비권장 (구식 보안 방식) |	✅ 권장 (최신 보안 표준)


---

## 9.🔖 용어 정리  
- ### 🔹 BoilerPlateCode  
  특정 언어나 프레임워크에서 필수적으로 포함해야 하는 코드 구조  
  (반복적으로 동일하게 사용되는 코드, IDE, 템플릿 엔진 등을 통해 자동 생성되는 코드, 프레임워크나 라이브러리에서 기본 제공하는 설정 코드) 

---
- ### 🔹 **인증(Authentication)과 인가(Authorization)란?**  
- **인증(Authentication)**: 사용자가 누구인지 확인하는 과정  
  - 예: 회사 출입문에서 직원 카드를 태그하면 "이 사람이 직원인가?"를 확인하는 것  
- **인가(Authorization)**: 인증된 사용자가 특정 기능을 사용할 수 있는지 결정하는 과정  
  - 예: 직원 카드를 태그해도 **사장실에는 접근할 수 없는 것처럼**, 사용자의 권한을 제한하는 것  

---
- ### 🔹 **Stateless(상태 없음) 방식이란?**  
- **서버가 사용자의 정보를 기억하지 않는 방식**  
- 예: **카페에서 주문할 때마다 신분증을 보여줘야 하는 시스템**  
- 서버가 고객 정보를 기억하지 않아서, **매번 로그인할 때 사용자 정보를 다시 보내야 함**  

---

## 10. 📌 참고 및 출처
- 📖 [Modern API Development with Spring 6 and Spring Boot 3](https://github.com/PacktPublishing/Modern-API-Development-with-Spring-6-and-Spring-Boot-3)
- 🔗 [Spring Security 공식 문서](https://docs.spring.io/spring-security/reference/servlet/architecture.html#servlet-security-filters)

🚀 이 문서는 Spring Security & JWT 학습을 위해 체계적으로 정리된 문서입니다. 
