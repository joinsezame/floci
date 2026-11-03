package io.github.hectorvent.floci.services.cognito;

import io.github.hectorvent.floci.core.common.AwsEndpoints;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CognitoAwsIssuerTest {

    @Test
    void readsThePoolIdFromEachPartitionIssuer() {
        assertPool("us-east-1", "cognito-idp.us-east-1.amazonaws.com", "us-east-1_AbCdEfGhI");
        assertPool("us-gov-west-1", "cognito-idp.us-gov-west-1.amazonaws.com", "us-gov-west-1_GovPool1");
        assertPool("cn-north-1", "cognito-idp.cn-north-1.amazonaws.com.cn", "cn-north-1_ChinaPool");
        assertPool("eusc-de-east-1", "cognito-idp.eusc-de-east-1.amazonaws.eu", "eusc-de-east-1_Sovereign");
    }

    @Test
    void acceptsACaseInsensitiveHost() {
        assertEquals(Optional.of("us-east-1_AbC"), CognitoAwsIssuer.poolId(
                "HTTPS://Cognito-IdP.US-EAST-1.AMAZONAWS.COM/us-east-1_AbC"));
    }

    @Test
    void rejectsIssuersThatAreNotAnAwsCognitoPool() {
        assertEquals(Optional.empty(), CognitoAwsIssuer.poolId(null));
        assertEquals(Optional.empty(), CognitoAwsIssuer.poolId(""));
        assertEquals(Optional.empty(), CognitoAwsIssuer.poolId(
                "http://localhost:4566/us-east-1_AbCdEfGhI"));
        assertEquals(Optional.empty(), CognitoAwsIssuer.poolId(
                "http://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI"));
        assertEquals(Optional.empty(), CognitoAwsIssuer.poolId(
                "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI/extra"));
        assertEquals(Optional.empty(), CognitoAwsIssuer.poolId(
                "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI/"));
        assertEquals(Optional.empty(), CognitoAwsIssuer.poolId(
                "https://cognito-idp.us-east-1.amazonaws.com"));
        assertEquals(Optional.empty(), CognitoAwsIssuer.poolId(
                "https://cognito-idp.us-east-1.amazonaws.com:443/us-east-1_AbCdEfGhI"));
        assertEquals(Optional.empty(), CognitoAwsIssuer.poolId(
                "https://user:pass@cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI"));
        assertEquals(Optional.empty(), CognitoAwsIssuer.poolId(
                "https://cognito-idp.not-a-region.amazonaws.com/us-east-1_AbCdEfGhI"));
        assertEquals(Optional.empty(), CognitoAwsIssuer.poolId(
                "https://login.example.com/us-east-1_AbCdEfGhI"));
        assertEquals(Optional.empty(), CognitoAwsIssuer.poolId("not a url"));
    }

    private static void assertPool(String region, String host, String poolId) {
        assertEquals(host, AwsEndpoints.host("cognito-idp", region));
        assertEquals(Optional.of(poolId), CognitoAwsIssuer.poolId("https://" + host + "/" + poolId));
    }
}
