package io.github.hectorvent.floci.services.cognito;

import io.github.hectorvent.floci.core.common.AwsEndpoints;
import io.github.hectorvent.floci.core.common.AwsPartitions;

import java.net.URI;
import java.util.Locale;
import java.util.Optional;

/**
 * Recognises the issuer URL AWS publishes for a Cognito user pool,
 * {@code https://cognito-idp.<region>.<dns-suffix>/<poolId>}, in every partition.
 *
 * <p>Floci mints tokens with {@code <base-url>/<poolId>} instead, because that is the URL its
 * discovery document is served from. Callers that are handed the AWS form (CDK's
 * {@code HttpUserPoolAuthorizer} writes it literally) use this to find the pool id and then
 * verify against the pool this emulator actually hosts.
 */
public final class CognitoAwsIssuer {

    private static final String HOST_LABEL = "cognito-idp.";

    private CognitoAwsIssuer() {
    }

    /**
     * The pool id in {@code issuer} when it is that pool's AWS issuer URL. Empty for any other
     * string, including Floci's own {@code <base-url>/<poolId>}.
     */
    public static Optional<String> poolId(String issuer) {
        if (issuer == null || issuer.isBlank()) {
            return Optional.empty();
        }
        URI uri;
        try {
            uri = URI.create(issuer);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getHost().isBlank()
                || uri.getUserInfo() != null || uri.getPort() != -1
                || uri.getRawQuery() != null || uri.getFragment() != null) {
            return Optional.empty();
        }
        String region = regionOf(uri.getHost());
        if (region == null || AwsPartitions.forRegion(region).isEmpty()) {
            return Optional.empty();
        }
        if (!AwsEndpoints.host("cognito-idp", region).equalsIgnoreCase(uri.getHost())) {
            return Optional.empty();
        }
        String path = uri.getPath();
        if (path == null || path.length() < 2 || path.charAt(0) != '/') {
            return Optional.empty();
        }
        String poolId = path.substring(1);
        if (poolId.isBlank() || poolId.indexOf('/') >= 0) {
            return Optional.empty();
        }
        return Optional.of(poolId);
    }

    private static String regionOf(String host) {
        return AwsPartitions.stripKnownDnsSuffix(host.toLowerCase(Locale.ROOT))
                .map(AwsPartitions.DnsSuffixMatch::prefix)
                .filter(prefix -> prefix.startsWith(HOST_LABEL) && prefix.length() > HOST_LABEL.length())
                .map(prefix -> prefix.substring(HOST_LABEL.length()))
                .orElse(null);
    }
}
