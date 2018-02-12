package com.github.vincentrussell.nexus3.x509.dn.security.plugin;

import com.github.vincentrussell.nexus3.x509.dn.security.plugin.servlet.ExtendedX509AuthenticationFilter;
import com.google.inject.AbstractModule;
import org.sonatype.nexus.security.FilterChainModule;

import javax.inject.Named;
import javax.inject.Singleton;

import static org.sonatype.nexus.security.FilterProviderSupport.filterKey;

@Named
public class X509DnAuthenticatingRealmModel  extends AbstractModule
{
    @Override
    protected void configure() {

        bind(filterKey("contentAuthcBasic")).to(ExtendedX509AuthenticationFilter.class).in(Singleton.class);


        install(new FilterChainModule()
        {
            @Override
            protected void configure() {
                addFilterChain( "/**", "noSessionCreation,contentAuthcBasic");
            }
        });

    }

}
