# 🌐 Security-JWT
🚀 **Spring Security & JWT**

---
## 🎯 목적
📘 [Modern API Development with Spring 6 and Spring Boot 3](https://github.com/PacktPublishing/Modern-API-Development-with-Spring-6-and-Spring-Boot-3/tree/main/Chapter06) 를 공부하며,  
Chapter 6의 내용을 개인적으로 정리하고 요약한 문서입니다.

---
## 🔑 핵심 개념 및 필수 용어

### 1️⃣ Spring Security 개요
🔹 **Spring Security 란?**  
Spring 기반 애플리케이션의 **인증(Authentication)** 과 **인가(Authorization)** 를 관리하는 보안 프레임워크입니다.  
🔖 [_Boilerplate Code_](#boilerplatecode-란)를 직접 작성하지 않고도 **표준화된 보안 기능(인증, 인가, 세션 관리, CSRF 보호 등)을 손쉽게 구현할 수 있도록 지원하는 라이브러리 기반 프레임워크**입니다.  
➡ **즉, 보안 관련 로직을 직접 구현할 필요 없이, Spring Security가 제공하는 기능을 활용하여 안전한 애플리케이션을 개발할 수 있습니다.**  

🔹 **Spring Security의 핵심 기능**  
✅ **인증(Authentication)** → 사용자가 누구인지 확인  
✅ **인가(Authorization)** → 사용자가 특정 리소스에 접근할 수 있는지 결정  
✅ **보안 필터(Security Filters)** → 요청과 응답을 가로채서 보안 검사 수행  
✅ **비밀번호 암호화(BCrypt)** → 안전한 비밀번호 저장  
✅ **CSRF/XSRF 보호** → CSRF 공격 방지  

🔹 **Spring Security의 라이브러리 및 Gradle 설정**  
Spring Boot 프로젝트에서 Security를 설정하는 방법

---

### 2️⃣ Spring Security 요청 처리 흐름  
🔹 **DispatcherServlet과 요청 흐름**  
- 클라이언트 → DispatcherServlet → Security Filter → 컨트롤러 → 서비스 → DB  

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
🔹 **JWT란?**  
- 토큰 기반 인증 방식으로 **Stateless(상태 없음) 방식**의 인증을 제공  
- 클라이언트가 로그인하면 JWT를 발급받고, 이후 요청마다 JWT를 포함하여 인증을 수행  

🔹 **JWT의 구조**  
- 🏷️ **헤더(Header)** → 서명 알고리즘, 토큰 유형 정보 포함  
- 📂 **페이로드(Payload)** → 클레임(등록, 공개, 비공개) 포함  
- 🔏 **서명(Signature)** → 무결성을 보장하는 서명  

🔹 **JWT vs 세션 기반 인증**  
| 비교 항목 | JWT | 세션 기반 인증 |
|----------|-----|---------------|
| 저장 방식 | 클라이언트 측 (토큰 저장) | 서버 측 (세션 저장) |
| 확장성 | 높음 (Stateless) | 낮음 (서버 메모리 부담) |
| 보안성 | 토큰 탈취 시 위험 | 세션 하이재킹 위험 |

🔹 **OAuth 2.0 리소스 서버 인증 (토큰 기반 인증)**  
- OAuth 2.0을 활용한 JWT 인증 방식과 Spring Security 적용 방법  
- 불투명 토큰(opaque token)과 JWT의 차이점  

---

### 4️⃣ 보안 강화 및 권한 부여  
🔹 **유저 구분과 권한 부여 (RBAC - Role-Based Access Control)**  
- 사용자의 역할(Role)에 따라 접근 권한을 부여하는 방식  
- `@Secured("ROLE_ADMIN")` → 특정 역할을 가진 사용자만 접근 가능  
- `@PreAuthorize("hasRole('USER')")` → 실행 전 권한 체크  
- `@PostAuthorize("returnObject.owner == authentication.name")` → 실행 후 반환 값 검증  

🔹 **비밀번호 해싱 (BCrypt)**  
- Spring Security는 비밀번호를 안전하게 저장하기 위해 `BCryptPasswordEncoder`를 제공  
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

🔹 **CSRF/XSRF (Cross-Site Request Forgery)**  
- CSRF 공격 방지를 위해 Spring Security는 기본적으로 CSRF 보호 기능을 활성화  
- REST API에서는 CSRF 보호를 **비활성화**하는 경우가 많음  
```java
http.csrf().disable();
```

🔹 **CORS (Cross-Origin Resource Sharing)**  
- 다른 출처에서의 API 호출을 허용하는 방법  
- `@CrossOrigin` 애너테이션을 사용하여 설정 가능  

🔹 **RSA (비대칭 키 암호화) & JWT 서명**  
- JWT를 서명하고 검증할 때 RSA 공개 키/개인 키 암호화를 사용할 수 있음  

🔹 **XSS (Cross-Site Scripting) 공격과 방어**  
- HTML 태그 삽입 공격을 방어하기 위해 input 값에 대한 검증 필요  
- Spring Security에서 기본적으로 XSS 방어 기능 제공  

---

## 🎯 최종 목표  
✅ Spring Security와 JWT를 활용하여 **유저 인증 및 권한 부여**를 안전하게 처리하는 방법을 익히고, API 보안 강화를 위한 다양한 기법을 이해하는 것.  

---

## 🔖 용어 정리  
- ### 🔹 BoilerPlateCode 란?  
  특정 언어나 프레임워크에서 필수적으로 포함해야 하는 코드 구조  
  (반복적으로 동일하게 사용되는 코드, IDE, 템플릿 엔진 등을 통해 자동 생성되는 코드, 프레임워크나 라이브러리에서 기본 제공하는 설정 코드)  

---

## 📌 참고 및 출처  
- 📖 [Modern API Development with Spring 6 and Spring Boot 3](https://github.com/PacktPublishing/Modern-API-Development-with-Spring-6-and-Spring-Boot-3)  
- 🔗 [SecurityFilterChain 종류 및 설명](https://docs.spring.io/spring-security/reference/servlet/architecture.html#servlet-security-filters)  

---
