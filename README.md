# 🌐 Spring Security & JWT 정리

## 🎯 목적

이 문서는 **Modern API Development with Spring 6 and Spring Boot 3** (Chapter 6)를 공부하며, **Spring Security와 JWT의 개념을 이해하고 API 보안을 강화하는 방법**을 정리한 것입니다.

---

## 🔑 핵심 개념 및 필수 용어

### 1️⃣ Spring Security 개요

**Spring Security란?**  
Spring 기반 애플리케이션의 **인증(Authentication)** 과 **인가(Authorization)** 를 관리하는 보안 프레임워크입니다.

#### 🔹 주요 기능
✅ **인증(Authentication)** → 사용자가 누구인지 확인  
✅ **인가(Authorization)** → 사용자가 특정 리소스에 접근할 수 있는지 결정  
✅ **보안 필터(Security Filters)** → 요청과 응답을 가로채 보안 검사 수행  
✅ **비밀번호 암호화(BCrypt)** → 안전한 비밀번호 저장  
✅ **CSRF/XSRF 보호** → CSRF 공격 방지  

#### 🔹 Spring Security 요청 처리 흐름
1. 클라이언트 → DispatcherServlet → Security Filter → 컨트롤러 → 서비스 → DB
2. 사용자가 로그인 정보를 입력하면 Security가 이를 확인
3. 로그인 성공 후 사용자의 정보를 DB에서 가져오고, 접근 권한을 결정

#### 🔹 SecurityFilterChain의 역할
- 요청을 가로채어 **인증(Authentication)과 인가(Authorization)** 수행
- **Pre-filter(프리 필터)** → 요청이 컨트롤러로 전달되기 전에 적용  
- **Post-filter(포스트 필터)** → 응답이 반환되기 전에 적용  

---

### 2️⃣ JWT (JSON Web Token) 기반 인증

**JWT란?**  
토큰 기반 인증 방식으로 **Stateless(상태 없음) 인증 방식**을 제공하며, 클라이언트가 로그인하면 JWT를 발급받고 이후 요청마다 JWT를 포함하여 인증 수행합니다.

#### 🔹 JWT 구조
- **Header(헤더)** → 서명 알고리즘, 토큰 유형 정보 포함
- **Payload(페이로드)** → 클레임(등록, 공개, 비공개) 포함
- **Signature(서명)** → 무결성을 보장하는 서명

#### 🔹 JWT vs 세션 기반 인증 비교
| 비교 항목 | JWT | 세션 기반 인증 |
|----------|-----|---------------|
| 저장 방식 | 클라이언트 측 (토큰 저장) | 서버 측 (세션 저장) |
| 확장성 | 높음 (Stateless) | 낮음 (서버 메모리 부담) |
| 보안성 | 토큰 탈취 시 위험 | 세션 하이재킹 위험 |

---

### 3️⃣ 보안 강화 및 권한 부여

#### 🔹 RBAC (Role-Based Access Control)
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

## 🔐 OAuth 2.0 개요

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

---

## 🔑 인증 및 인가 흐름

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

## 📖 보안 개념 쉽게 이해하기

### 🔹 불투명 토큰(Opaque Token) vs JWT
| 비교 항목 | 불투명 토큰 (Opaque Token) | JWT |
|----------|-----------------|------|
| 저장 방식 | 서버에서 관리 | 클라이언트가 직접 보관 |
| 검증 방식 | 서버에 요청해야 확인 가능 | 토큰만으로 검증 가능 |
| 예제 | 신용카드(승인 필요) | 영화관 표(바로 사용 가능) |

### 🔹 CSRF (크로스 사이트 요청 위조)
✔️ **방어 방법**:
```java
http.csrf().enable();
```

### 🔹 XSS (크로스 사이트 스크립팅)
✔️ **방어 방법**:
```java
http.headers().xssProtection();
```

---

