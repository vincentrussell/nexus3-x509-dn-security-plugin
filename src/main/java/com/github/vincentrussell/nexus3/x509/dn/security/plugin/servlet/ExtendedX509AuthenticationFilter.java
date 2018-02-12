package com.github.vincentrussell.nexus3.x509.dn.security.plugin.servlet;

import com.github.vincentrussell.nexus3.x509.dn.security.plugin.api.ExtendedX509AuthenticationToken;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.filter.authc.X509AuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Named;
import javax.inject.Singleton;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.security.cert.X509Certificate;

@Named
@Singleton
public class ExtendedX509AuthenticationFilter extends X509AuthenticationFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger( ExtendedX509AuthenticationFilter.class );

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response )
            throws Exception
    {
        X509Certificate[] clientCertChain = ( X509Certificate[] ) request.getAttribute( "javax.servlet.request.X509Certificate" );
        LOGGER.info( "X509AuthFilter.createToken() cert chain is {}", clientCertChain );
        if ( clientCertChain == null || clientCertChain.length < 1 ) {
            throw new ShiroException( "Request do not contain any X509Certificate" );
        }
        return new ExtendedX509AuthenticationToken( clientCertChain, getHost( request ) );
    }

}
