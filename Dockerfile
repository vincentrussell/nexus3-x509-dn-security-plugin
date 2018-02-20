FROM maven:3.5.2 as builder
MAINTAINER vincent.russell@gmail.com
COPY . /build
WORKDIR /build
RUN mvn clean package

FROM sonatype/nexus3:3.7.1
USER root
RUN mkdir -p /opt/sonatype/nexus/system/com/github/vincentrussell/nexus3-x509-dn-security-plugin/1.0/
COPY src/main/resources/certs /opt/sonatype/nexus/system/com/github/vincentrussell/nexus3-x509-dn-security-plugin/1.0/
RUN mkdir -p /opt/sonatype/nexus/system/com/github/vincentrussell/nexus3-x509-dn-security-plugin/1.0/
COPY --from=builder /build/target/nexus3-x509-dn-security-plugin-1.0.jar /opt/sonatype/nexus/system/com/github/vincentrussell/nexus3-x509-dn-security-plugin/1.0/
#COPY /target/nexus3-x509-dn-security-plugin-1.0.jar /opt/sonatype/nexus/system/com/github/vincentrussell/nexus3-x509-dn-security-plugin/1.0/
RUN echo "reference\:file\:com/github/vincentrussell/nexus3-x509-dn-security-plugin/1.0/nexus3-x509-dn-security-plugin-1.0.jar = 200" >> /opt/sonatype/nexus/etc/karaf/startup.properties
RUN mkdir -p /opt/sonatype/nexus/etc/jetty/etc
COPY src/main/resources/certs/keystore.jks /opt/sonatype/nexus/etc/jetty/etc/keystore.jks
COPY src/main/resources/config/jetty.xml /opt/sonatype/nexus/etc/jetty
COPY src/main/resources/config/jetty-ssl.xml /opt/sonatype/nexus/etc/jetty
COPY src/main/resources/config/jetty-https.xml /opt/sonatype/nexus/etc/jetty
COPY src/main/resources/config/nexus-default.properties /opt/sonatype/nexus/etc
COPY src/main/resources/config/nexus.vmoptions /opt/sonatype/nexus/bin
COPY src/main/resources/config/x509-dn-security-config.yaml /opt/sonatype/nexus/etc

RUN chown -R nexus:nexus /opt/sonatype/nexus/

EXPOSE 5005

USER nexus
