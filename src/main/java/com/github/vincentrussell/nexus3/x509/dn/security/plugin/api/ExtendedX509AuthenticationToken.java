package com.github.vincentrussell.nexus3.x509.dn.security.plugin.api;

import org.apache.shiro.authc.x509.X509AuthenticationToken;

import java.security.cert.X509Certificate;

public class ExtendedX509AuthenticationToken extends X509AuthenticationToken {

    public ExtendedX509AuthenticationToken(X509Certificate[] clientCertChain, String host) {
        super(clientCertChain, host);
    }

    @Override
    public Object getCredentials()
    {
        return getSubjectDN().getName();
    }
}
