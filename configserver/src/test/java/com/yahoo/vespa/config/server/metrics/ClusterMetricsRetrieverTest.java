package com.yahoo.vespa.config.server.metrics;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import junit.framework.AssertionFailedError;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiConsumer;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.Assert.*;


/**
 * @author olaa
 */
public class ClusterMetricsRetrieverTest {

    @Rule
    public final WireMockRule wireMock = new WireMockRule(options().port(8080), true);

    @Test
    public void testMetricAggregation() throws IOException {
        List<URI> hosts = List.of(URI.create("http://localhost:8080/1"), URI.create("http://localhost:8080/2"), URI.create("http://localhost:8080/3"));

        stubFor(get(urlEqualTo("/1"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(contentMetrics())));

        stubFor(get(urlEqualTo("/2"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(contentMetrics())));

        stubFor(get(urlEqualTo("/3"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(containerMetrics())));

        ClusterInfo expectedContentCluster = new ClusterInfo("content_cluster_id", "content");
        ClusterInfo expectedContainerCluster = new ClusterInfo("container_cluster_id", "container");

        Map<ClusterInfo, MetricsAggregator> aggregatorMap = new ClusterMetricsRetriever().requestMetricsGroupedByCluster(hosts);

        compareAggregators(
                new MetricsAggregator().addDocumentCount(6000.0),
                aggregatorMap.get(expectedContentCluster)
        );

        compareAggregators(
                new MetricsAggregator()
                        .addContainerLatency(3000, 43)
                        .addContainerLatency(2000, 0)
                        .addQrLatency(3000, 43)
                        .addFeedLatency(3000, 43),
                aggregatorMap.get(expectedContainerCluster)

        );
        wireMock.stop();
    }

    private String containerMetrics() throws IOException {
        return Files.readString(Path.of("src/test/resources/metrics/container_metrics"));
    }

    private String contentMetrics() throws IOException {
        return Files.readString(Path.of("src/test/resources/metrics/content_metrics"));
    }

    // Same tolerance value as used internally in MetricsAggregator.isZero
    private static final double metricsTolerance = 0.001;

    private void compareAggregators(MetricsAggregator expected, MetricsAggregator actual) {
        BiConsumer<Double, Double> assertDoubles = (a, b) -> assertEquals(a.doubleValue(), b.doubleValue(), metricsTolerance);

        compareOptionals(expected.aggregateDocumentCount(), actual.aggregateDocumentCount(), assertDoubles);
        compareOptionals(expected.aggregateQueryRate(), actual.aggregateQueryRate(), assertDoubles);
        compareOptionals(expected.aggregateFeedRate(), actual.aggregateFeedRate(), assertDoubles);
        compareOptionals(expected.aggregateQueryLatency(), actual.aggregateQueryLatency(), assertDoubles);
        compareOptionals(expected.aggregateFeedLatency(), actual.aggregateFeedLatency(), assertDoubles);
    }

    @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
    private static <T> void compareOptionals(Optional<T> a, Optional<T> b, BiConsumer<T, T> comparer) {
        if (a.isPresent() != b.isPresent()) throw new AssertionFailedError("Both optionals are not present: " + a + ", " + b);
        a.ifPresent(x -> b.ifPresent(y -> comparer.accept(x, y)));
    }
}