package io.github.hectorvent.floci.services.apigatewayv2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.ContainerCaBundle;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.PublicKeys;
import io.github.hectorvent.floci.core.common.SsrfProtection;
import io.github.hectorvent.floci.services.cognito.CognitoAwsIssuer;
import io.github.hectorvent.floci.services.cognito.CognitoService;
import io.github.hectorvent.floci.services.cognito.model.UserPool;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.SystemDefaultDnsResolver;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.core5.util.Timeout;
import org.jboss.logging.Logger;

import javax.net.ssl.SSLContext;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Verifies the RS256 signature of a token presented to an HTTP API v2 JWT authorizer, the same
 * way real API Gateway does: fetch {@code {issuer}/.well-known/openid-configuration} to discover
 * {@code jwks_uri}, fetch the JWK Set from there, select the key matching the token's {@code kid},
 * and verify. Auth0, Okta, and a Cognito pool this emulator does not host stay on that path.
 *
 * <p>With TLS on, an issuer Floci serves itself (a Cognito pool's URL) presents a certificate of
 * Floci's CA, which the JVM's default trust store does not hold. The issuer is fetched trusting the
 * CA bundle Floci gives every container it launches, so a JWT authorizer on a Floci pool verifies
 * its tokens as API Gateway verifies a Cognito pool's on AWS.
 *
 * <p>Per-issuer JWKS are cached (see {@link #CACHE_TTL}) so repeat requests to the same route
 * don't refetch the discovery document and key set on every call.
 *
 * <p>One issuer shape is resolved in-process. When {@code issuer} is the AWS Cognito URL of a user
 * pool this emulator hosts ({@code https://cognito-idp.<region>.<dns-suffix>/<poolId>}, the value
 * CDK's {@code HttpUserPoolAuthorizer} writes), the token is checked against that pool's own
 * signing key and {@link #verify} returns the local issuer Floci minted into the token. The public
 * URL does not publish this pool's key, and the local issuer is an HTTP address the default
 * private-network policy refuses to fetch. A pool this emulator does not host is left on the HTTP
 * path. A hosted pool whose key does not verify the token is rejected here: it is not retried
 * against the public URL.
 *
 * <p>Fails closed: a network error, an unreachable issuer, an unsupported algorithm ({@code none}
 * included), or no matching key are all treated as verification failure, not as "unverifiable, so
 * allow." A local emulator that can't reach the real issuer must reject, since silently accepting
 * would reopen exactly the unauthenticated-claims gap this class exists to close.
 */
@ApplicationScoped
public class JwtSignatureVerifier implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(JwtSignatureVerifier.class);

    private static final Duration CACHE_TTL = Duration.ofMinutes(10);
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(10);

    private final ObjectMapper objectMapper;
    private final CloseableHttpClient httpClient;
    private final boolean allowPrivateNetworkTargets;
    private final CognitoService cognitoService;
    private final Map<String, CachedJwks> jwksCache = new ConcurrentHashMap<>();

    @Inject
    public JwtSignatureVerifier(ObjectMapper objectMapper, EmulatorConfig config, CognitoService cognitoService) {
        this(objectMapper, SystemDefaultDnsResolver.INSTANCE,
                config.security().allowPrivateJwtTargets(), ContainerCaBundle.sslContext(config).orElse(null),
                cognitoService);
    }

    /** Tests that exercise the HTTP path and have no Cognito service to consult. */
    public JwtSignatureVerifier(ObjectMapper objectMapper, EmulatorConfig config) {
        this(objectMapper, config, null);
    }

    /**
     * Injects the DNS boundary so tests can verify address policy without using external DNS.
     */
    JwtSignatureVerifier(
            ObjectMapper objectMapper,
            DnsResolver dnsResolver,
            boolean allowPrivateNetworkTargets
    ) {
        this(objectMapper, dnsResolver, allowPrivateNetworkTargets, null);
    }

    /**
     * As above, trusting {@code sslContext}'s anchors over HTTPS, or the JVM's default ones when it
     * is null.
     */
    JwtSignatureVerifier(
            ObjectMapper objectMapper,
            DnsResolver dnsResolver,
            boolean allowPrivateNetworkTargets,
            SSLContext sslContext
    ) {
        this(objectMapper, dnsResolver, allowPrivateNetworkTargets, sslContext, null);
    }

    /**
     * As above, consulting {@code cognitoService} when the configured issuer is the AWS URL of a
     * pool this emulator hosts. Null leaves every issuer on the HTTP path.
     */
    JwtSignatureVerifier(
            ObjectMapper objectMapper,
            DnsResolver dnsResolver,
            boolean allowPrivateNetworkTargets,
            SSLContext sslContext,
            CognitoService cognitoService
    ) {
        this.objectMapper = objectMapper;
        this.allowPrivateNetworkTargets = allowPrivateNetworkTargets;
        this.cognitoService = cognitoService;

        ConnectionConfig connectionConfig = ConnectionConfig.custom()
                .setConnectTimeout(Timeout.of(HTTP_TIMEOUT))
                .setSocketTimeout(Timeout.of(HTTP_TIMEOUT))
                .build();
        PoolingHttpClientConnectionManagerBuilder connectionManagerBuilder = PoolingHttpClientConnectionManagerBuilder.create()
                .setDnsResolver(new JwtDnsResolver(dnsResolver, allowPrivateNetworkTargets))
                .setDefaultConnectionConfig(connectionConfig);
        if (sslContext != null) {
            connectionManagerBuilder.setTlsSocketStrategy(ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext)
                    .buildClassic());
        }
        PoolingHttpClientConnectionManager connectionManager = connectionManagerBuilder.build();
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(Timeout.of(HTTP_TIMEOUT))
                .setResponseTimeout(Timeout.of(HTTP_TIMEOUT))
                .setRedirectsEnabled(false)
                .build();
        this.httpClient = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setDefaultRequestConfig(requestConfig)
                .disableRedirectHandling()
                .disableAutomaticRetries()
                .disableCookieManagement()
                .build();
    }

    public static class JwtVerificationException extends Exception {
        public JwtVerificationException(String message) {
            super(message);
        }

        public JwtVerificationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private record CachedJwks(Map<String, RSAPublicKey> keysByKid, Instant fetchedAt) {
        boolean isExpired() {
            return Instant.now().isAfter(fetchedAt.plus(CACHE_TTL));
        }
    }

    /**
     * Verifies {@code token}'s signature against {@code issuer}'s published JWKS.
     *
     * @return the issuer claim the token must carry. This is {@code issuer}, except when
     *         {@code issuer} names a Cognito pool hosted here: the signature is checked against
     *         that pool's key and the result is the local issuer the token was minted with.
     * @throws JwtVerificationException if the token is not RS256, the issuer's discovery/JWKS
     *                                   endpoints are unreachable or malformed, no key matches the
     *                                   token's {@code kid}, or the signature does not verify.
     */
    public String verify(String token, String issuer) throws JwtVerificationException {
        if (issuer == null || issuer.isBlank()) {
            throw new JwtVerificationException("JWT authorizer has no configured issuer");
        }
        String[] parts = token == null ? new String[0] : token.split("\\.", -1);
        if (parts.length != 3) {
            throw new JwtVerificationException("Token is not a well-formed JWT");
        }

        JsonNode header = decodeJson(parts[0])
                .orElseThrow(() -> new JwtVerificationException("Token header is not valid JSON"));
        String alg = header.path("alg").asText("");
        if (!"RS256".equals(alg)) {
            throw new JwtVerificationException(
                    "Unsupported token signing algorithm: " + (alg.isEmpty() ? "none" : alg));
        }
        String kid = header.path("kid").asText(null);
        if (kid == null || kid.isBlank()) {
            throw new JwtVerificationException("Token header has no kid");
        }

        Optional<UserPool> hosted = hostedPool(issuer);
        if (hosted.isPresent()) {
            verifyHostedPool(parts, kid, hosted.get(), issuer);
            return cognitoService.getIssuer(hosted.get().getId());
        }

        RSAPublicKey key = resolveKey(issuer, kid);
        if (key == null) {
            throw new JwtVerificationException(
                    "No JWKS key matches kid '" + kid + "' for issuer " + issuer);
        }

        if (!signatureValid(parts[0] + "." + parts[1], parts[2], key)) {
            throw new JwtVerificationException("Token signature is invalid");
        }
        return issuer;
    }

    private Optional<UserPool> hostedPool(String issuer) {
        if (cognitoService == null) {
            return Optional.empty();
        }
        Optional<String> poolId = CognitoAwsIssuer.poolId(issuer);
        if (poolId.isEmpty()) {
            return Optional.empty();
        }
        try {
            return Optional.of(cognitoService.describeUserPool(poolId.get()));
        } catch (AwsException expected) {
            // Not a pool this emulator hosts. The caller fetches the issuer over HTTP.
            return Optional.empty();
        }
    }

    private void verifyHostedPool(String[] parts, String kid, UserPool pool, String issuer)
            throws JwtVerificationException {
        String keyId;
        RSAPublicKey key;
        try {
            keyId = cognitoService.getSigningKeyId(pool);
            key = cognitoService.getSigningPublicKey(pool);
        } catch (RuntimeException e) {
            throw new JwtVerificationException(
                    "Could not load the signing key for issuer " + issuer, e);
        }
        if (keyId == null || keyId.isBlank() || key == null || !keyId.equals(kid)) {
            throw new JwtVerificationException(
                    "No JWKS key matches kid '" + kid + "' for issuer " + issuer);
        }
        if (!signatureValid(parts[0] + "." + parts[1], parts[2], key)) {
            throw new JwtVerificationException("Token signature is invalid");
        }
    }

    private RSAPublicKey resolveKey(String issuer, String kid) throws JwtVerificationException {
        CachedJwks cached = jwksCache.get(issuer);
        if (cached != null && !cached.isExpired()) {
            RSAPublicKey key = cached.keysByKid().get(kid);
            if (key != null) {
                return key;
            }
            // A cached-but-stale key set (e.g. the issuer rotated keys) is worth one refetch
            // before giving up, rather than waiting out the full TTL.
        }

        Map<String, RSAPublicKey> fetched = fetchJwks(issuer);
        jwksCache.put(issuer, new CachedJwks(fetched, Instant.now()));
        return fetched.get(kid);
    }

    Map<String, RSAPublicKey> fetchJwks(String issuer) throws JwtVerificationException {
        String jwksUri = fetchJwksUri(issuer);
        JsonNode jwks = httpGetJson(jwksUri, "JWKS document");

        JsonNode keys = jwks.path("keys");
        if (!keys.isArray()) {
            throw new JwtVerificationException("JWKS document at " + jwksUri + " has no keys array");
        }

        Map<String, RSAPublicKey> result = new ConcurrentHashMap<>();
        for (JsonNode jwk : keys) {
            String kty = jwk.path("kty").asText("");
            String kid = jwk.path("kid").asText(null);
            if (!"RSA".equals(kty) || kid == null || kid.isBlank()) {
                continue; // non-RSA or unidentifiable keys can't back an RS256 check
            }
            String n = jwk.path("n").asText(null);
            String e = jwk.path("e").asText(null);
            if (n == null || e == null) {
                continue;
            }
            try {
                result.put(kid, toRsaPublicKey(n, e));
            } catch (GeneralSecurityException | IllegalArgumentException ex) {
                LOG.debugv("Skipping unparsable JWKS entry for issuer {0}, kid {1}: {2}",
                        issuer, kid, ex.getMessage());
            }
        }
        return result;
    }

    String fetchJwksUri(String issuer) throws JwtVerificationException {
        String discoveryUrl = issuer.replaceAll("/+$", "") + "/.well-known/openid-configuration";
        JsonNode discovery = httpGetJson(discoveryUrl, "OIDC discovery document");
        String jwksUri = discovery.path("jwks_uri").asText(null);
        if (jwksUri == null || jwksUri.isBlank()) {
            throw new JwtVerificationException(
                    "OIDC discovery document at " + discoveryUrl + " has no jwks_uri");
        }
        return jwksUri;
    }

    private JsonNode httpGetJson(String url, String description) throws JwtVerificationException {
        URI target = validateTarget(url, description);
        try {
            FetchedDocument response = httpClient.execute(
                    ClassicRequestBuilder.get(target).build(),
                    apacheResponse -> new FetchedDocument(
                            apacheResponse.getCode(),
                            apacheResponse.getEntity() == null
                                    ? new byte[0]
                                    : EntityUtils.toByteArray(apacheResponse.getEntity())));
            if (response.statusCode() != 200) {
                throw new JwtVerificationException(
                        "Fetching " + description + " from " + url + " returned HTTP " + response.statusCode());
            }
            return objectMapper.readTree(response.body());
        } catch (JwtVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new JwtVerificationException("Failed to fetch " + description + " from " + url, e);
        }
    }

    private URI validateTarget(String url, String description) throws JwtVerificationException {
        URI target;
        try {
            target = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new JwtVerificationException("Invalid " + description + " URL: " + url, e);
        }
        String scheme = target.getScheme();
        if (target.getHost() == null || target.getHost().isBlank() || target.getUserInfo() != null) {
            throw new JwtVerificationException("JWT " + description + " has an invalid host: " + url);
        }
        InetAddress literalAddress = literalAddress(target.getHost());
        boolean privateLiteral = literalAddress != null && SsrfProtection.isBlockedAddress(literalAddress);
        boolean privateHttp = allowPrivateNetworkTargets
                && "http".equalsIgnoreCase(scheme)
                && privateLiteral;
        if (!"https".equalsIgnoreCase(scheme) && !privateHttp) {
            throw new JwtVerificationException("JWT " + description + " must use HTTPS: " + url);
        }
        if (!allowPrivateNetworkTargets && privateLiteral) {
            throw new JwtVerificationException(
                    "JWT " + description + " resolves to a private or local address: " + target.getHost());
        }
        return target;
    }

    private static InetAddress literalAddress(String host) {
        if (host.indexOf(':') < 0 && !host.matches("[0-9]{1,3}(?:\\.[0-9]{1,3}){3}")) {
            return null;
        }
        try {
            return InetAddress.ofLiteral(host);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    @PreDestroy
    @Override
    public void close() {
        try {
            httpClient.close();
        } catch (Exception e) {
            LOG.debugv("Could not close JWT document client: {0}", e.getMessage());
        }
    }

    private record FetchedDocument(int statusCode, byte[] body) {
    }

    record JwtDnsResolver(DnsResolver delegate, boolean allowPrivateNetworkTargets) implements DnsResolver {
        @Override
        public InetAddress[] resolve(String host) throws UnknownHostException {
            InetAddress[] addresses = delegate.resolve(host);
            if (addresses == null || addresses.length == 0) {
                throw new UnknownHostException("JWT target host has no addresses: " + host);
            }
            if (!allowPrivateNetworkTargets) {
                for (InetAddress address : addresses) {
                    if (SsrfProtection.isBlockedAddress(address)) {
                        throw new UnknownHostException(
                                "JWT target host resolves to a private or local address: " + host);
                    }
                }
            }
            return addresses.clone();
        }

        @Override
        public String resolveCanonicalHostname(String host) {
            return host;
        }
    }

    private RSAPublicKey toRsaPublicKey(String n, String e) throws GeneralSecurityException {
        return PublicKeys.rsa(new BigInteger(1, Base64.getUrlDecoder().decode(padBase64(n))),
                new BigInteger(1, Base64.getUrlDecoder().decode(padBase64(e))));
    }

    private boolean signatureValid(String signingInput, String encodedSignature, RSAPublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return signature.verify(Base64.getUrlDecoder().decode(padBase64(encodedSignature)));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            LOG.debugv("JWT signature check failed: {0}", e.getMessage());
            return false;
        }
    }

    private Optional<JsonNode> decodeJson(String base64UrlSegment) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(padBase64(base64UrlSegment));
            JsonNode node = objectMapper.readTree(decoded);
            return node != null && node.isObject() ? Optional.of(node) : Optional.empty();
        } catch (IllegalArgumentException | IOException e) {
            return Optional.empty();
        }
    }

    private static String padBase64(String base64) {
        return switch (base64.length() % 4) {
            case 2 -> base64 + "==";
            case 3 -> base64 + "=";
            default -> base64;
        };
    }
}
