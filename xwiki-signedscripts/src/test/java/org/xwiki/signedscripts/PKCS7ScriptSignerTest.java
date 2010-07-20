/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.signedscripts;

import java.security.GeneralSecurityException;

import org.jmock.Expectations;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.xwiki.crypto.x509.X509CryptoService;
import org.xwiki.signedscripts.framework.AbstractSignedScriptsTest;
import org.xwiki.signedscripts.internal.PKCS7ScriptSigner;
import org.xwiki.test.annotation.MockingRequirement;


/**
 * Tests {@link PKCS7ScriptSigner}.
 * 
 * @version $Id$
 * @since 2.5
 */
public class PKCS7ScriptSignerTest extends AbstractSignedScriptsTest
{
    /** The tested script signer component. */
    @MockingRequirement
    PKCS7ScriptSigner signer;

    /**
     * {@inheritDoc}
     * @see org.xwiki.test.AbstractMockingComponentTestCase#setUp()
     */
    @Before
    @Override
    public void setUp() throws Exception
    {
        super.setUp();

        // key manager
        final String kpFingerprint = getTestKeyPair().getFingerprint();
        final KeyManager mockKeyManager = getComponentManager().lookup(KeyManager.class);
        getMockery().checking(new Expectations() {{
            allowing(mockKeyManager).getCertificate(with(kpFingerprint));
                will(returnValue(getTestKeyPair().getCertificate()));
            allowing(mockKeyManager).getKeyPair(with(kpFingerprint));
                will(returnValue(getTestKeyPair()));
        }});
        // crypto service
        final X509CryptoService mockCrypto = getComponentManager().lookup(X509CryptoService.class);
        getMockery().checking(new Expectations() {{
            allowing(mockCrypto).signText(with(any(String.class)), with(getTestKeyPair()), with("passwrd"));
                will(returnValue("/TEST+SIGNATURE/"));
            allowing(mockCrypto).verifyText(with(any(String.class)), with("/TEST+SIGNATURE/"));
                will(returnValue(getTestKeyPair().getCertificate()));
            allowing(mockCrypto).verifyText(with(any(String.class)), with("*ERROR*"));
                will(returnValue(getTestCert()));
        }});
    }

    @Test
    public void testSign() throws GeneralSecurityException
    {
        final String code = "{{groovy}}println();{{/groovy}}\n";
        SignedScript script = signer.sign(code, getTestKeyPair().getFingerprint(), "passwrd");
        Assert.assertEquals(code, script.getCode());
        Assert.assertEquals(getTestKeyPair().getFingerprint(), script.get(SignedScriptKey.FINGERPRINT));
    }

    @Test
    public void testSignVerify() throws GeneralSecurityException
    {
        final String code = "{{groovy}}println();{{/groovy}}\n";
        SignedScript script = signer.sign(code, getTestKeyPair().getFingerprint(), "passwrd");
        // NOTE: the test may fail randomly if the next second starts at this line 
        SignedScript verified = signer.getVerifiedScript(script.serialize());
        Assert.assertEquals(script.serialize(), verified.serialize());
    }

    @Test
    public void testExternalSignIsSign() throws GeneralSecurityException
    {
        final String code = "{{groovy}}println();{{/groovy}}\n";
        final SignedScript signed = signer.sign(code, getTestKeyPair().getFingerprint(), "passwrd");
        // NOTE: the test may fail randomly if the next second starts at this line 
        SignedScript prepared = signer.prepareScriptForSigning(code, getTestKeyPair().getFingerprint());
        String signature = "/TEST+SIGNATURE/";
        SignedScript script = signer.constructSignedScript(prepared, signature);
        Assert.assertEquals(signed.serialize(), script.serialize());
    }

    @Test(expected = GeneralSecurityException.class)
    public void testPreparedNotVerify() throws GeneralSecurityException
    {
        final String code = "{{groovy}}println();{{/groovy}}\n";
        SignedScript prepared = signer.prepareScriptForSigning(code, getTestKeyPair().getFingerprint());
        // the test relies on the fact that an unsigned script has the string *ERROR* instead of the signature
        signer.getVerifiedScript(prepared.serialize());
        Assert.fail("Prepared script passed verification");
    }
}
