# civic-api

[![](https://jitpack.io/v/MosquitoKill3r/civic-api.svg)](https://jitpack.io/#MosquitoKill3r/civic-api)

Java port for the Civic hosted SIP API.
Please see [docs.civic.com](https://docs.civic.com) for a more details.

### Installation
* You must have **Gradle** installed in order to build this project
* You can check [Demo Web Application](https://github.com/MosquitoKill3r/civic-api-web-demo) for configuration, installation and usage.
* To build project run `gradle clean build` from command line.
* To run unit test execute `gradle test` from command line.

### Usage
- Register your application on [Civic Partner Portal](https://sip-partners.civic.com).
- In your code init `CivicConfig` object with your *Application ID*, *Application Secret*, *Application Private Signing Key*, *Public Key* (see below), and *Environment* (using `prod`).
```java
publis static final String PUB_HEX_KEY = "049a45998638cfb3c4b211d72030d9ae8329a242db63bfb0076a54e7647370a8ac5708b57af6065805d5a6be72332620932dbb35e8d318fce18e7c980a0eb26aa1";
```
- Create new instance of `CivicSip` object with provided configuration.
- Exchange JWT token for user data:
```java
CivicSip civicSip = new CivicSip(config);
UserData userData = civicSip.exchangeToken(jwt);
```
That's it.

### Dependencies
**Gradle** dependencies:
```gradle
    compile("com.fasterxml.jackson.core:jackson-databind:2.8.10")
    compile("org.bouncycastle:bcprov-jdk15on:1.55")
    compile("org.apache.httpcomponents:httpclient:4.5.4")
    compile("io.jsonwebtoken:jjwt:0.9.0")
```