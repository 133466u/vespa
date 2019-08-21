package ai.vespa.hosted.cd;

import ai.vespa.hosted.api.EndpointAuthenticator;
import ai.vespa.hosted.cd.metric.Metrics;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * An endpoint in a Vespa application {@link Deployment}, which allows document and metrics retrieval.
 *
 * @author jonmv
 */
public interface Endpoint {

    /** Returns the URI of the endpoint, with scheme, host and port. */
    URI hostUri();

    /** Sends the given request with required authentication. See {@link EndpointAuthenticator#authenticated} and {@link HttpClient#send}. */
    <T> HttpResponse<T> send(HttpRequest.Builder request, HttpResponse.BodyHandler<T> handler);

    /** Sends the given request with required authentication. */
    default HttpResponse<String> send(HttpRequest.Builder request) {
        return send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }



}
