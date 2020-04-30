// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.jdisc.http.core;

import org.eclipse.jetty.server.HttpConnection;
import org.eclipse.jetty.server.ServerConnector;

import javax.servlet.http.HttpServletRequest;

/**
 * @author bjorncs
 */
public class HttpServletRequestUtils {
    private HttpServletRequestUtils() {}

    public static HttpConnection getConnection(HttpServletRequest request) {
        return (HttpConnection)request.getAttribute("org.eclipse.jetty.server.HttpConnection");
    }

    /**
     * Note: {@link HttpServletRequest#getLocalPort()} may return the local port of the load balancer / reverse proxy if proxy-protocol is enabled.
     * @return the actual local port of the underlying Jetty connector
     */
    public static int getConnectorLocalPort(HttpServletRequest request) {
        ServerConnector jettyConnector = (ServerConnector) getConnection(request).getConnector();
        return jettyConnector.getLocalPort();
    }

}
