# 🌐 Security-JWT
🚀 **Spring Security & JWT**

---
## 🎯 목적
📘 [Modern-API-Development-with-Spring-6-and-Spring-Boot-3](https://github.com/PacktPublishing/Modern-API-Development-with-Spring-6-and-Spring-Boot-3/tree/main/Chapter06) 를 공부하며, Chapter 6의 내용을 개인적으로 정리하고 요약한 문서입니다.

---
## 🔑 핵심 개념 및 필수 용어

### 1️⃣ Spring Security 개요
🔹 **DispatcherServlet과 요청 흐름**: Spring MVC에서 요청이 처리되는 과정과 Security Filter의 역할  
🔹 **SecurityFilterChain의 종류**: Spring Security의 다양한 필터 체인과 보안 관리 방식  
🔹 **Spring Security의 라이브러리 및 Gradle 설정**: Spring Boot 프로젝트에서 Security를 설정하는 방법  

### 2️⃣ 인증 및 권한 부여
🔹 **OAuth 2.0 리소스 서버 인증 (토큰 기반 인증)**: OAuth 2.0을 활용한 인증 방식과 Spring Security 적용 방법  
🔹 **JWT의 구조**:
   - 🏷️ **헤더(Header)**: 서명 알고리즘, 토큰 유형 정보 포함
   - 📂 **페이로드(Payload)**: 클레임(등록, 공개, 비공개) 포함
   - 🔏 **서명(Signature)**: 무결성을 보장하는 서명  
🔹 **불투명 토큰(opaque token)과 JWT의 차이점**  
🔹 **Stateless 방식의 호출**: 세션을 사용하지 않고 각 요청에서 인증 정보를 포함하는 방식  
🔹 **유저 구분과 권한 부여**: 역할 기반 접근 제어 (RBAC) 적용  

### 3️⃣ 보안 강화
🔹 **비밀번호 해싱 (bcrypt)**: 안전한 비밀번호 저장을 위한 해싱 기법  
🔹 **CSRF/XSRF (Cross-Site Request Forgery)**: CSRF 공격 방지 및 Spring Security에서의 처리 방식  
🔹 **CORS (Cross-Origin Resource Sharing)**: 다른 출처에서의 API 호출을 허용하는 방법  
🔹 **RSA (비대칭 키 암호화)**: JWT 서명 및 암호화에 사용되는 공개 키/개인 키 방식  
🔹 **CSR (Client-Side Rendering)과 보안 고려사항**  
🔹 **XSS (Cross-Site Scripting) 공격과 방어**  

---
## 🎯 최종 목표
✅ Spring Security와 JWT를 활용하여 **유저 인증 및 권한 부여**를 안전하게 처리하는 방법을 익히고, API 보안 강화를 위한 다양한 기법을 이해하는 것.  

---
## 📌 참고 및 출처
- 📖 [Modern API Development with Spring 6 and Spring Boot 3](https://github.com/PacktPublishing/Modern-API-Development-with-Spring-6-and-Spring-Boot-3)  
- 🔗 [SecurityFilterChain 종류 및 설명](https://docs.spring.io/spring-security/reference/servlet/architecture.html#servlet-security-filters)  

