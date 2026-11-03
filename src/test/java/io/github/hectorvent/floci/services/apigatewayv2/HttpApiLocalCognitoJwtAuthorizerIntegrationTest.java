package io.github.hectorvent.floci.services.apigatewayv2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import io.github.hectorvent.floci.core.common.Base64Url;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static io.github.hectorvent.floci.services.cognito.CognitoRestAssuredUtils.cognitoAction;
import static io.github.hectorvent.floci.services.cognito.CognitoRestAssuredUtils.cognitoJson;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CDK's {@code HttpUserPoolAuthorizer} sets the JWT issuer to
 * {@code https://cognito-idp.<region>.amazonaws.com/<poolId>}. Floci mints tokens whose {@code iss}
 * is {@code <base-url>/<poolId>}, the same value the pool's discovery document publishes.
 * A real token from that pool must pass the authorizer, and the claim forwarded downstream must
 * still be the local issuer.
 */
@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HttpApiLocalCognitoJwtAuthorizerIntegrationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String PASSWORD = "Perm1234!";
    private static final AtomicReference<String> receivedIss = new AtomicReference<>();

    private static HttpServer backend;
    private static String poolId;
    private static String clientId;
    private static String localIssuer;
    private static String awsIssuer;
    private static String idToken;
    private static String accessToken;
    private static String httpApiId;

    @BeforeAll
    static void startBackend() throws Exception {
        RestAssuredJsonUtils.configureAwsContentTypes();

        backend = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        backend.createContext("/", exchange -> {
            receivedIss.set(exchange.getRequestHeaders().getFirst("x-iss"));
            byte[] body = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        backend.start();
    }

    @AfterAll
    static void stopBackend() {
        if (backend != null) {
            backend.stop(0);
        }
    }

    @Test
    @Order(1)
    void setUpPoolAndApi() throws Exception {
        poolId = cognitoJson("CreateUserPool", """
                {"PoolName": "HttpJwtIssuerPool"}
                """).path("UserPool").path("Id").asText();
        assertTrue(poolId.startsWith("us-east-1_"), poolId);
        localIssuer = "http://localhost:4566/" + poolId;
        awsIssuer = "https://cognito-idp.us-east-1.amazonaws.com/" + poolId;

        clientId = cognitoJson("CreateUserPoolClient", """
                {"UserPoolId": "%s", "ClientName": "http-jwt",
                 "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]}
                """.formatted(poolId)).path("UserPoolClient").path("ClientId").asText();
        cognitoAction("AdminCreateUser", """
                {"UserPoolId": "%s", "Username": "alice", "MessageAction": "SUPPRESS"}
                """.formatted(poolId)).then().statusCode(200);
        cognitoAction("AdminSetUserPassword", """
                {"UserPoolId": "%s", "Username": "alice", "Password": "%s", "Permanent": true}
                """.formatted(poolId, PASSWORD)).then().statusCode(200);
        JsonNode tokens = cognitoJson("InitiateAuth", """
                {"ClientId": "%s", "AuthFlow": "USER_PASSWORD_AUTH",
                 "AuthParameters": {"USERNAME": "alice", "PASSWORD": "%s"}}
                """.formatted(clientId, PASSWORD)).path("AuthenticationResult");
        idToken = tokens.path("IdToken").asText();
        accessToken = tokens.path("AccessToken").asText();

        httpApiId = given()
                .contentType(ContentType.JSON)
                .body("""
                        {"name":"local-cognito-jwt-authorizer","protocolType":"HTTP"}
                        """)
                .when().post("/v2/apis")
                .then().statusCode(201)
                .extract().path("apiId");
        given()
                .contentType(ContentType.JSON)
                .body("""
                        {"stageName":"test"}
                        """)
                .when().post("/v2/apis/" + httpApiId + "/stages")
                .then().statusCode(201);
        String backendUrl = "http://127.0.0.1:" + backend.getAddress().getPort();
        String integrationId = given()
                .contentType(ContentType.JSON)
                .body("""
                        {"integrationType":"HTTP_PROXY","integrationUri":"%s","payloadFormatVersion":"1.0","requestParameters":{"append:header.x-iss":"$context.authorizer.claims.iss"}}
                        """.formatted(backendUrl))
                .when().post("/v2/apis/" + httpApiId + "/integrations")
                .then().statusCode(201)
                .extract().path("integrationId");
        String authorizerId = given()
                .contentType(ContentType.JSON)
                .body("""
                        {"authorizerType":"JWT","name":"cognito-aws-issuer","identitySource":["$request.header.Authorization"],"jwtConfiguration":{"issuer":"%s","audience":["%s"]}}
                        """.formatted(awsIssuer, clientId))
                .when().post("/v2/apis/" + httpApiId + "/authorizers")
                .then().statusCode(201)
                .extract().path("authorizerId");
        given()
                .contentType(ContentType.JSON)
                .body("""
                        {"routeKey":"GET /hello","authorizationType":"JWT","authorizerId":"%s","target":"integrations/%s"}
                        """.formatted(authorizerId, integrationId))
                .when().post("/v2/apis/" + httpApiId + "/routes")
                .then().statusCode(201);
    }

    @Test
    @Order(10)
    void mintedIssStaysLocalAndTheAwsShapedAuthorizerAcceptsIt() throws Exception {
        assertEquals(localIssuer, jwtPayload(idToken).path("iss").asText());
        assertEquals(localIssuer, jwtPayload(accessToken).path("iss").asText());
        assertNotEquals(awsIssuer, jwtPayload(idToken).path("iss").asText());
        given()
                .when().get("/" + poolId + "/.well-known/openid-configuration")
                .then().statusCode(200)
                .body("issuer", equalTo(localIssuer));

        receivedIss.set(null);
        given()
                .header("Authorization", "Bearer " + idToken)
                .when().get("/execute-api/" + httpApiId + "/test/hello")
                .then().statusCode(200);
        assertEquals(localIssuer, receivedIss.get());

        receivedIss.set(null);
        given()
                .header("Authorization", "Bearer " + accessToken)
                .when().get("/execute-api/" + httpApiId + "/test/hello")
                .then().statusCode(200);
        assertEquals(localIssuer, receivedIss.get());
    }

    @Test
    @Order(11)
    void tamperedSignatureIsRejected() {
        String tampered = idToken.substring(0, idToken.length() - 2) + "aa";
        given()
                .header("Authorization", "Bearer " + tampered)
                .when().get("/execute-api/" + httpApiId + "/test/hello")
                .then().statusCode(401)
                .body("message", equalTo("Unauthorized"));
    }

    @Test
    @Order(12)
    void tokenFromAnotherPoolIsRejected() throws Exception {
        String otherPoolId = cognitoJson("CreateUserPool", """
                {"PoolName": "HttpJwtIssuerOtherPool"}
                """).path("UserPool").path("Id").asText();
        try {
            String otherClientId = cognitoJson("CreateUserPoolClient", """
                    {"UserPoolId": "%s", "ClientName": "other",
                     "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"]}
                    """.formatted(otherPoolId)).path("UserPoolClient").path("ClientId").asText();
            cognitoAction("AdminCreateUser", """
                    {"UserPoolId": "%s", "Username": "bob", "MessageAction": "SUPPRESS"}
                    """.formatted(otherPoolId)).then().statusCode(200);
            cognitoAction("AdminSetUserPassword", """
                    {"UserPoolId": "%s", "Username": "bob", "Password": "%s", "Permanent": true}
                    """.formatted(otherPoolId, PASSWORD)).then().statusCode(200);
            String otherToken = cognitoJson("InitiateAuth", """
                    {"ClientId": "%s", "AuthFlow": "USER_PASSWORD_AUTH",
                     "AuthParameters": {"USERNAME": "bob", "PASSWORD": "%s"}}
                    """.formatted(otherClientId, PASSWORD)).path("AuthenticationResult").path("IdToken").asText();
            assertEquals("http://localhost:4566/" + otherPoolId, jwtPayload(otherToken).path("iss").asText());

            given()
                    .header("Authorization", "Bearer " + otherToken)
                    .when().get("/execute-api/" + httpApiId + "/test/hello")
                    .then().statusCode(401)
                    .body("message", equalTo("Unauthorized"));
        } finally {
            cognitoAction("DeleteUserPool", """
                    {"UserPoolId": "%s"}
                    """.formatted(otherPoolId)).then().statusCode(200);
        }
    }

    @Test
    @Order(999)
    void cleanup() {
        if (httpApiId != null) {
            given().when().delete("/v2/apis/" + httpApiId);
        }
        if (poolId != null) {
            cognitoAction("DeleteUserPool", """
                    {"UserPoolId": "%s"}
                    """.formatted(poolId)).then().statusCode(200);
        }
    }

    private static JsonNode jwtPayload(String token) throws Exception {
        return MAPPER.readTree(Base64Url.decode(token.split("\\.", -1)[1]));
    }
}
