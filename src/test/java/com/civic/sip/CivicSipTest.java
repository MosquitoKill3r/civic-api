package com.civic.sip;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringBufferInputStream;
import java.io.StringReader;
import java.security.PrivateKey;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.civic.sip.config.CivicConfig;
import com.civic.sip.model.UserData;
import com.civic.sip.model.UserDataRecord;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.jsonwebtoken.JwtBuilder;


@RunWith(MockitoJUnitRunner.class)
public class CivicSipTest {

    private CivicSip subject;

    @Mock
    private HttpClient mockClient;
    @Mock
    private HttpResponse mockResponse;
    @Mock
    private StatusLine mockStatusLine;
    @Mock
    private HttpEntity mockEntity;
    @Mock
    private JwtBuilder mockJwtBuilder;
    @Mock
    private PrivateKey mockPrivateKey;

    @Captor
    private ArgumentCaptor<String> contentNodeCaptor;
    @Captor
    private ArgumentCaptor<Map> headerCaptor;
    @Captor
    private ArgumentCaptor<ObjectNode> objectNodeArgumentCaptor;

    @Before
    public void setup() {
        CivicConfig config = new CivicConfig("appID", "appSecret", "privateKey", "publicKey", "env");
        CivicSip sip = new CivicSip(config);
        subject = Mockito.spy(sip);
    }

    @Test
    public void exchangeToken_shouldExchangeJWTTokenToUserData() throws Exception {
        doReturn(null).when(subject).makeAuthorizationHeader(any());
        doReturn(null).when(subject).verifyAndDecrypt(any());
        doReturn(mockClient).when(subject).createHttpClient();
        UserData toBeReturned = new UserData();
        doReturn(toBeReturned).when(subject).verifyAndDecrypt(objectNodeArgumentCaptor.capture());

        when(mockClient.execute(any())).thenReturn(mockResponse);
        when(mockResponse.getStatusLine()).thenReturn(mockStatusLine);
        when(mockResponse.getEntity()).thenReturn(mockEntity);
        when(mockStatusLine.getStatusCode()).thenReturn(200);

        String mockData = "{\"key\":\"value\"}";
        ByteArrayInputStream is = new ByteArrayInputStream(mockData.getBytes("UTF-8"));
        when(mockEntity.getContent()).thenReturn(is);

        UserData userData = subject.exchangeToken("mocktoken");

        ObjectNode captorValue = objectNodeArgumentCaptor.getValue();
        assertThat(captorValue.has("key"), is(true));
        assertThat(captorValue.get("key").asText(), is("value"));

        assertThat(userData, is(toBeReturned));
    }

    @Test
    public void makeAuthorizationHeader() throws Exception {
        String body = "{authToken: \"token\"}";

        doReturn("_requestToken_").when(subject).createToken();
        doReturn("_extToken_").when(subject).createCivicExt(body);

        String auth = subject.makeAuthorizationHeader(body);

        assertThat(auth, is("Civic _requestToken_._extToken_"));
        verify(subject).createToken();
        verify(subject).createCivicExt(body);
    }

    @Test
    public void createToken() throws Exception {
        doReturn(mockJwtBuilder).when(subject).createJwtBuilder();
        doReturn(mockPrivateKey).when(subject).getPrivateKeyFromHex();

        when(mockJwtBuilder.setHeader(any(Map.class))).thenReturn(mockJwtBuilder);
        when(mockJwtBuilder.setPayload(any())).thenReturn(mockJwtBuilder);
        when(mockJwtBuilder.compact()).thenReturn("--mock_signed_token--");
        String token = subject.createToken();

        assertThat(token, is("--mock_signed_token--"));

        verify(mockJwtBuilder).setPayload(contentNodeCaptor.capture());
        verify(mockJwtBuilder).setHeader(headerCaptor.capture());
        String payload = contentNodeCaptor.getValue();
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode contentNode = mapper.readValue(payload, ObjectNode.class);

        assertThat(contentNode.has("jti"), is(true));
        assertThat(contentNode.has("nbf"), is(true));
        assertThat(contentNode.has("iat"), is(true));
        assertThat(contentNode.has("exp"), is(true));
        assertThat(contentNode.get("iss").asText(), is("appID"));
        assertThat(contentNode.get("sub").asText(), is("appID"));
        assertThat(contentNode.get("aud").asText(), is("https://api.civic.com/sip"));
        assertThat(contentNode.has("data"), is(true));

        JsonNode data = contentNode.get("data");
        assertThat(data.get("method").asText(), is("POST"));
        assertThat(data.get("path").asText(), is("scopeRequest/authCode"));

        Map header = headerCaptor.getValue();
        assertThat(header.get("alg"), is("ES256"));
    }

    @Test
    public void createCivicExt() {
        String ext = subject.createCivicExt("payload");
        assertThat(ext, is(notNullValue()));
        assertThat(ext, is("AI/hTB1Bpn0wSnGnGBfVfcWTKYLca142Are/1mLSTfA="));
    }

    @Test
    public void verifyAndDecrypt() throws Exception {
        String sUserData = "[{\"label\":\"testLabel\",\"value\":\"testValue\",\"isValid\":true,\"isOwner\":true}]";

        String mockData = "Some mock data";

        doReturn(sUserData).when(subject).verify(mockData);
        doReturn(sUserData).when(subject).decrypt(sUserData);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode payload = mapper.createObjectNode();
        payload.put("encrypted", true);
        payload.put("data", mockData);

        UserData userData = subject.verifyAndDecrypt(payload);
        UserData expected = new UserData()
                .setUserDataRecords(mapper.readValue(sUserData,
                        mapper.getTypeFactory().constructCollectionType(List.class, UserDataRecord.class)));

        assertThat(userData.getUserDataRecords().size(), is(1));

        UserDataRecord userDataRecord = userData.getUserDataRecords().get(0);
        UserDataRecord expectedUserDataRecord = expected.getUserDataRecords().get(0);

        assertThat(userDataRecord.getLabel(), is(expectedUserDataRecord.getLabel()));
        assertThat(userDataRecord.getValue(), is(expectedUserDataRecord.getValue()));
        assertThat(userDataRecord.getIsOwner(), is(expectedUserDataRecord.getIsOwner()));
        assertThat(userDataRecord.getIsValid(), is(expectedUserDataRecord.getIsValid()));

        verify(subject).verify(any());
        verify(subject).decrypt(any());
    }
}
