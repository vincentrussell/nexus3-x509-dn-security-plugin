package com.github.vincentrussell.nexus3.x509.dn.security.plugin.servlet;

import com.github.vincentrussell.nexus3.x509.dn.security.plugin.api.ExtendedX509AuthenticationToken;
import org.apache.shiro.authc.AuthenticationToken;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.security.auth.x500.X500Principal;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;

public class ExtendedX509AuthenticationFilterTest {

    private MockHttpServletRequest mockHttpServletRequest;
    private MockHttpServletResponse mockHttpServletResponse;
    private ExtendedX509AuthenticationFilter extendedX509AuthenticationFilter;

    @Before
    public void setup() {
        mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletResponse = new MockHttpServletResponse();
        extendedX509AuthenticationFilter = new ExtendedX509AuthenticationFilter();
    }


    @Test
    public void processX509() throws Exception {
        MockHttpServletRequest request = x509("keystore.cer").postProcessRequest(
                mockHttpServletRequest);
        AuthenticationToken token = extendedX509AuthenticationFilter.createToken(request, mockHttpServletResponse);
        assertTrue(ExtendedX509AuthenticationToken.class.isInstance(token));
        String dn = "CN=Firstname Lastname,OU=Unknown,O=Unknown,L=Annapolis Junction,ST=MD,C=US";
        assertEquals(dn, ((X500Principal)token.getPrincipal()).getName());
        assertEquals("localhost", ((ExtendedX509AuthenticationToken)token).getHost());
        assertEquals(dn,token.getCredentials());
    }




}
