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

#### 🔹 JWT vs 세션 기반 인증 비교
| 비교 항목 | JWT | 세션 기반 인증 |
|----------|-----|---------------|
| 저장 방식 | 클라이언트 측 (토큰 저장) | 서버 측 (세션 저장) |
| 확장성 | 높음 (Stateless) | 낮음 (서버 메모리 부담) |
| 보안성 | 토큰 탈취 시 위험 | 세션 하이재킹 위험 |

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
🔹 **RSA (비대칭 키 암호화) & JWT 서명**  
- JWT를 서명하고 검증할 때 RSA 공개 키/개인 키 암호화를 사용할 수 있음  


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
