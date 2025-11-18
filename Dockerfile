# ---------------------------------
# 1. 빌드(Build) 단계
# ---------------------------------
# Gradle(JDK 21 포함) 이미지를 'builder'라는 이름으로 사용
# (프로젝트의 Java 버전에 맞게 11, 17, 21 등으로 수정)
FROM gradle:8.14.3-jdk21 AS builder

# 빌드 환경에 Node.js(npm) 설치
# (프로젝트의 Node.js 버전에 맞게 16.x, 18.x 등으로 수정)
RUN apt-get update && \
    apt-get install -y curl && \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs

WORKDIR /workspace

# --- Docker 캐시 최적화 ---
# 1. 빌드/의존성 관련 파일을 먼저 복사합니다.
# (이 파일들이 변경되지 않으면 2번 단계는 캐시를 사용합니다)
COPY build.gradle settings.gradle gradlew ./
# gradle/wrapper 디렉터리도 명시적으로 복사
COPY gradle ./gradle

# 2. 의존성을 먼저 다운로드 받습니다. (이 작업이 별도의 레이어로 캐시됩니다)
RUN ./gradlew dependencies --info

# 3. 실제 소스 코드를 복사합니다.
# (소스 코드만 변경될 경우, 1, 2번은 캐시를 재사용하고 3번부터 다시 시작합니다)
COPY . .

# Gradle 실행 권한 부여 및 빌드 실행
# 이 명령어 하나가 React 설치, React 빌드, Spring 빌드를 모두 처리합니다.
RUN chmod +x ./gradlew
RUN ./gradlew build -x test

# ---------------------------------
# 2. 실행(Runtime) 단계
# ---------------------------------
# Alpine 기반의 경량 JRE 이미지 사용
FROM bellsoft/liberica-openjdk-alpine:21
WORKDIR /app

# 'builder' 단계에서 생성된 최종 .jar 파일을 복사
# /workspace/build/libs/ 에서 *.jar 파일을 찾아 app.jar 로 복사
COPY --from=builder /workspace/build/libs/*.jar app.jar

# 환경변수로 Spring Boot 데이터베이스 설정 (필요시 docker-compose.yml 등에서 설정)
# ENV SPRING_DATASOURCE_URL=...
# ENV SPRING_DATASOURCE_USERNAME=...
# ENV SPRING_DATASOURCE_PASSWORD=...

# 컨테이너가 노출할 포트 (스프링 부트 기본 포트 8080)
EXPOSE 8080

# 컨테이너가 시작될 때 실행할 명령어
ENTRYPOINT ["java", "-jar", "app.jar"]