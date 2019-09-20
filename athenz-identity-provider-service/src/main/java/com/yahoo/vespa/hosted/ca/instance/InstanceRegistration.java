// Copyright 2019 Oath Inc. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.hosted.ca.instance;

import com.yahoo.security.Pkcs10Csr;

import java.util.Objects;

/**
 * Information for registering a new instance in the system. This is similar to the InstanceRegisterInformation type in
 * ZTS.
 *
 * @author mpolden
 */
public class InstanceRegistration {

    private final String provider;
    private final String domain;
    private final String service;
    private final String attestationData;
    private final Pkcs10Csr csr;

    public InstanceRegistration(String provider, String domain, String service, String attestationData, Pkcs10Csr csr) {
        this.provider = Objects.requireNonNull(provider, "provider must be non-null");
        this.domain = Objects.requireNonNull(domain, "domain must be non-null");
        this.service = Objects.requireNonNull(service, "service must be non-null");
        this.attestationData = Objects.requireNonNull(attestationData, "attestationData must be non-null");
        this.csr = Objects.requireNonNull(csr, "csr must be non-null");
    }

    /** The provider which issued the attestation data contained in this */
    public String provider() {
        return provider;
    }

    /** Athenz domain of the instance */
    public String domain() {
        return domain;
    }

    /** Athenz service of the instance */
    public String service() {
        return service;
    }

    /** Host document describing this instance (received from config server) */
    public String attestationData() {
        return attestationData;
    }

    public Pkcs10Csr csr() {
        return csr;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        InstanceRegistration that = (InstanceRegistration) o;
        return provider.equals(that.provider) &&
               domain.equals(that.domain) &&
               service.equals(that.service) &&
               attestationData.equals(that.attestationData) &&
               csr.equals(that.csr);
    }

    @Override
    public int hashCode() {
        return Objects.hash(provider, domain, service, attestationData, csr);
    }

    @Override
    public String toString() {
        return "InstanceRegistration{" +
               "provider='" + provider + '\'' +
               ", domain='" + domain + '\'' +
               ", service='" + service + '\'' +
               ", attestationData='" + attestationData + '\'' +
               ", csr=" + csr +
               '}';
    }
}
