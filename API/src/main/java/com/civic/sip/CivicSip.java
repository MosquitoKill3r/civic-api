package com.civic.sip;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import com.civic.sip.config.CivicConfig;
import com.civic.sip.model.UserData;
import com.civic.sip.model.UserDataRecord;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class CivicSip {
    private static final String BASE_URL = "https://api.civic.com/sip";
    private static final String AUTH_PATH = "scopeRequest/authCode";

    private final CivicConfig config;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public CivicSip(CivicConfig config) {
        this.config = config;
        Security.addProvider(new BouncyCastleProvider());
    }

    public UserData exchangeToken(String jwtToken) throws Exception {
        ObjectNode bodyNode = MAPPER.createObjectNode();
        bodyNode.put("authToken", jwtToken);

        String body = bodyNode.toString();
        String auth = makeAuthorizationHeader(body);


        HttpClient client = HttpClientBuilder.create().build();
        HttpPost post = new HttpPost(BASE_URL + "/" + config.getEnvironment() + "/" + AUTH_PATH);

        post.addHeader("Authorization", auth);
        post.addHeader("Accept", "application/json");
        post.addHeader("Content-Type", "application/json");

        post.setEntity(new StringEntity(body, ContentType.APPLICATION_JSON));

        HttpResponse response = client.execute(post);
        int statusCode = response.getStatusLine().getStatusCode();

        if (statusCode == 200) {
            InputStream is = response.getEntity().getContent();

            ObjectNode jsonNodes = MAPPER.readValue(is, ObjectNode.class);

            return verifyAndDecrypt(jsonNodes);
        } else {
            throw new RuntimeException(String.format("Civic responded with %s status code", statusCode));
        }
    }

    private String makeAuthorizationHeader(String body) throws Exception {
        String requestToken = createToken();
        String extToken = createCivicExt(body);
        return String.format("Civic %s.%s", requestToken, extToken);
    }

    private String createToken() throws Exception {

        long now = System.currentTimeMillis();
        long till = now + 3 * 60000;

        ObjectNode contentNode = MAPPER.createObjectNode();
        contentNode.put("jti", UUID.randomUUID().toString());
        contentNode.put("nbf", (now + 60000) / 1000);
        contentNode.put("iat", now / 1000);
        contentNode.put("exp", till / 1000);
        contentNode.put("iss", config.getApplicationId());
        contentNode.put("aud", BASE_URL);
        contentNode.put("sub", config.getApplicationId());

        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("method", "POST");
        payload.put("path", AUTH_PATH);
        contentNode.set("data", payload);


        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "ES256");
//        headers.put("typ", "JWT");
        JwtBuilder builder = Jwts.builder();
        builder
                .setHeader(headers)
                .setPayload(contentNode.toString());
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.ES256;

        PrivateKey ecdsa = getPrivateKeyFromHex();

        builder.signWith(signatureAlgorithm, ecdsa);
        return builder.compact();
    }

    private PrivateKey getPrivateKeyFromHex() throws Exception {
        X9ECParameters ecCurve = ECNamedCurveTable.getByName("secp256r1");
        ECParameterSpec ecParameterSpec
                = new ECNamedCurveSpec("secp256r1", ecCurve.getCurve(), ecCurve.getG(), ecCurve.getN(),
                ecCurve.getH(), ecCurve.getSeed());
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(config.getPrivateKey(), 16),
                ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        return keyFactory.generatePrivate(privateKeySpec);
    }

    private String createCivicExt(String body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(config.getApplicationSecret().getBytes(), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] binaryData = mac.doFinal(body.getBytes());
            return Base64.encodeBase64String(binaryData);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private UserData verifyAndDecrypt(ObjectNode payload) throws Exception {
        String data = payload.get("data").asText();
        boolean encrypted = payload.get("encrypted").asBoolean();

        //validate
        String decodedToken = verify(data);
        if (decodedToken == null) {
            throw new RuntimeException("Returned data is not valid");
        }

        String clearData = decodedToken;
        if (encrypted) {
            clearData = decrypt(clearData);
        }

        UserData result = new UserData();
        result.setUserDataRecords(MAPPER.readValue(clearData,
                MAPPER.getTypeFactory().constructCollectionType(List.class, UserDataRecord.class)));

        return result;
    }

    private String verify(String data) throws Exception {
        JwtParser parser = Jwts.parser();
        PublicKey pubKey = getPublicKeyFromHexString();

        Claims body = parser.setAllowedClockSkewSeconds(60)
                .setSigningKey(pubKey)
                .parseClaimsJws(data).getBody();
        return body.get("data", String.class);
    }

    private PublicKey getPublicKeyFromHexString() throws Exception {
        byte[] hex2 = DatatypeConverter.parseHexBinary(config.getPublicKey());

        ECNamedCurveParameterSpec spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1");
        KeyFactory factory = KeyFactory.getInstance("ECDSA");

        ECNamedCurveSpec params
                = new ECNamedCurveSpec("secp256r1", spec.getCurve(), spec.getG(), spec.getN(), spec.getH());

        ECPoint point = ECPointUtil.decodePoint(params.getCurve(), hex2);
        java.security.spec.ECPublicKeySpec publicKeySpec = new java.security.spec.ECPublicKeySpec(point, params);
        return factory.generatePublic(publicKeySpec);
    }

    private String decrypt(String encodedData) throws Exception {
        byte[] iv = DatatypeConverter.parseHexBinary(encodedData.substring(0, 32));
        String messagePart = encodedData.substring(32);
        byte[] encodedPart = Base64.decodeBase64(messagePart);

        byte[] pkBytes = DatatypeConverter.parseHexBinary(config.getApplicationSecret());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        SecretKeySpec secretKeySpec = new SecretKeySpec(pkBytes, "AES");
        IvParameterSpec ivSpect = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpect);

        byte[] decodedBytes = cipher.doFinal(encodedPart);
        return new String(decodedBytes);
    }

}