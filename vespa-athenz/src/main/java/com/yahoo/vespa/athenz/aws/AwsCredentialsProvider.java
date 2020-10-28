// Copyright Verizon Media. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.athenz.aws;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.yahoo.vespa.athenz.api.AthenzDomain;
import com.yahoo.vespa.athenz.api.AwsRole;
import com.yahoo.vespa.athenz.api.AwsTemporaryCredentials;
import com.yahoo.vespa.athenz.client.zts.DefaultZtsClient;
import com.yahoo.vespa.athenz.client.zts.ZtsClient;
import com.yahoo.vespa.athenz.identity.ServiceIdentityProvider;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Implementation of {@link AWSCredentialsProvider} that uses {@link ZtsClient} to retrieve temporary credentials.
 *
 * @author tokle
 */
public class AwsCredentialsProvider implements AWSCredentialsProvider {

    private final static Duration MIN_EXPIRY = Duration.ofMinutes(5);
    private final AthenzDomain athenzDomain;
    private final AwsRole awsRole;
    private final ZtsClient ztsClient;
    private volatile AwsTemporaryCredentials credentials;

    public AwsCredentialsProvider(ZtsClient ztsClient, AthenzDomain athenzDomain, AwsRole awsRole) {
        this.ztsClient = ztsClient;
        this.athenzDomain = athenzDomain;
        this.awsRole = awsRole;
        this.credentials = getAthenzTempCredentials();
    }

    public AwsCredentialsProvider(URI ztsUrl, ServiceIdentityProvider identityProvider, AthenzDomain athenzDomain, AwsRole awsRole) {
        this(new DefaultZtsClient(ztsUrl, identityProvider), athenzDomain, awsRole);
    }

    public AwsCredentialsProvider(URI ztsUrl, SSLContext sslContext, AthenzDomain athenzDomain, AwsRole awsRole) {
        this(new DefaultZtsClient(ztsUrl, sslContext), athenzDomain, awsRole);
    }

    /**
     * Requests temporary credentials from ZTS or return cached credentials
     */
    private AwsTemporaryCredentials getAthenzTempCredentials() {
        if(shouldRefresh(credentials)) {
            this.credentials = ztsClient.getAwsTemporaryCredentials(athenzDomain, awsRole);
        }
        return credentials;
    }

    @Override
    public AWSCredentials getCredentials() {
        AwsTemporaryCredentials creds = getAthenzTempCredentials();
        return new BasicSessionCredentials(creds.accessKeyId(), creds.secretAccessKey(), creds.sessionToken());
    }

    @Override
    public void refresh() {
        getAthenzTempCredentials();
    }

    /*
     * Checks credential expiration, returns true if it will expipre in the next MIN_EXPIRY minutes
     */
    static boolean shouldRefresh(AwsTemporaryCredentials credentials) {
        Instant expiration = Optional.ofNullable(credentials).map(AwsTemporaryCredentials::expiration).orElse(Instant.EPOCH);
        return Duration.between(Instant.now(), expiration).toMinutes() < MIN_EXPIRY.toMinutes();
    }
}
