FROM openjdk:8-jre-alpine3.9

COPY target/pki-api-1.jar /pki.jar

CMD ["java", "-jar", "/pki.jar"]