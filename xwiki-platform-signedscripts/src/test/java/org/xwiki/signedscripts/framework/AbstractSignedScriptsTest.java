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
package org.xwiki.signedscripts.framework;

import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.jmock.Expectations;
import org.jmock.States;
import org.jmock.api.Action;
import org.jmock.api.Invocation;
import org.junit.Before;
import org.xwiki.crypto.internal.UserDocumentUtils;
import org.xwiki.crypto.x509.XWikiX509Certificate;
import org.xwiki.crypto.x509.XWikiX509KeyPair;
import org.xwiki.crypto.x509.internal.DefaultXWikiX509KeyPair;
import org.xwiki.signedscripts.internal.CryptoStorageUtils;
import org.xwiki.test.AbstractComponentTestCase;


/**
 * Base class for tests that need certificates and key pairs.
 * 
 * @version $Id$
 * @since 2.5
 */
public abstract class AbstractSignedScriptsTest extends AbstractComponentTestCase
{
    /** The document storing all trusted certificates. */
    private static final String TRUSTED_DOC = "XWiki.TrustedCertificates";

    /** Fingerprint of the test certificate. */
    private static final String CERT_FP = "eb31104d2fb1bc8495cf39e75124aef3f9ab7bfb";

    /** PEM encoded test certificate (XWiki SAS Web Certificate). */
    private static final String CERT_PEM = "-----BEGIN CERTIFICATE-----\n"
        + "MIIDWTCCAsKgAwIBAgIDEl9SMA0GCSqGSIb3DQEBBQUAME4xCzAJBgNVBAYTAlVT\n"
        + "MRAwDgYDVQQKEwdFcXVpZmF4MS0wKwYDVQQLEyRFcXVpZmF4IFNlY3VyZSBDZXJ0\n"
        + "aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTAwNDE2MDI0NTU3WhcNMTEwNTE5MDEzNjIw\n"
        + "WjCB4zEpMCcGA1UEBRMgQnZ2MGF3azJ0VUhSOVBCdG9VdndLbEVEYVBpbkpoanEx\n"
        + "CzAJBgNVBAYTAkZSMRcwFQYDVQQKFA4qLnh3aWtpc2FzLmNvbTETMBEGA1UECxMK\n"
        + "R1Q0MDc0ODAzNjExMC8GA1UECxMoU2VlIHd3dy5yYXBpZHNzbC5jb20vcmVzb3Vy\n"
        + "Y2VzL2NwcyAoYykxMDEvMC0GA1UECxMmRG9tYWluIENvbnRyb2wgVmFsaWRhdGVk\n"
        + "IC0gUmFwaWRTU0woUikxFzAVBgNVBAMUDioueHdpa2lzYXMuY29tMIGfMA0GCSqG\n"
        + "SIb3DQEBAQUAA4GNADCBiQKBgQCSiflt/i6ZlqNODL8LQLPwNfXEdb3J+II1NXye\n"
        + "InrU3yRCybF7DG8NGIrvy+0o40YI+I4Q1Fcvv890IObdQdHmFtz8OKzKXT+giEG7\n"
        + "LxJXW3DDb9NckOsbjbNuNFSA9E/aQalrxbDVWyO0droG1v3vDBmG/KzfQkPmoE8g\n"
        + "P4qPsQIDAQABo4GuMIGrMB8GA1UdIwQYMBaAFEjmaPkr0rKV10fYIyAQTzOYkJ/U\n"
        + "MA4GA1UdDwEB/wQEAwIE8DAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\n"
        + "OgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9z\n"
        + "ZWN1cmVjYS5jcmwwHQYDVR0OBBYEFHbS5h/MPHDXIIn5ived2HiF6AwiMA0GCSqG\n"
        + "SIb3DQEBBQUAA4GBALPfA0VQS9pCFYl9co6k3AYLx+gWg6FsTn3aYZRjS9Eeg2qR\n"
        + "f7XuiIlq2ZLb1r0SA8Unn2uw2wrHXnqw2I/AARawI/vT4toKGjJwLB8cONLE6cyO\n"
        + "rC4qW/5AUann6D1r26EWLSGYh62AcX/jUT4bjoWLhMhblxyLOgbBe8uYPLMH\n"
        + "-----END CERTIFICATE-----\n";

    /** PEM encoded test key pair. Password: "passwrd" */
    private final static String KP_PEM = "-----BEGIN XWIKI CERTIFICATE AND PRIVATE KEY-----\n"
        + "rO0ABXNyADZvcmcueHdpa2kuY3J5cHRvLng1MDkuaW50ZXJuYWwuRGVmYXVsdFhX\n"
        + "aWtpWDUwOUtleVBhaXIAAAAAAAAAAQIAA1sAEmVuY29kZWRDZXJ0aWZpY2F0ZXQA\n"
        + "AltCWwAbcGFzc3dvcmRFbmNyeXB0ZWRQcml2YXRlS2V5cQB+AAFMABNwcml2YXRl\n"
        + "S2V5QWxnb3JpdGhtdAASTGphdmEvbGFuZy9TdHJpbmc7eHB1cgACW0Ks8xf4BghU\n"
        + "4AIAAHhwAAADMjCCAy4wggIWoAMCAQICBgEqOmGt5TANBgkqhkiG9w0BAQUFADAd\n"
        + "MRswGQYKCZImiZPyLGQBAQwLWFdpa2kuQWRtaW4wHhcNMTAwODAzMjI1NTM0WhcN\n"
        + "MTEwODAzMjM1NTM0WjAdMRswGQYKCZImiZPyLGQBAQwLWFdpa2kuQWRtaW4wggEi\n"
        + "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCLjEUl9YYkiSDzkPZWky8fGIDz\n"
        + "enLeTXWiRTvhwF9+H/i4bT299N+PybQp1rzEX1t64mI0wTanYTBWp+0JdwmQvmuf\n"
        + "gH4R4XNLbnnACU4DpNC0kVD1SgKdDL/u4S4oRSDCaFkJ2zlOo7I0SRLmUYlTSbf2\n"
        + "ujQsANggdXg+Z3lT7ACiC1eigbb0KsTtyAgjUPJOu4K0cJHuvG5FNNACIe91oRm3\n"
        + "05H96tgTCPqR+wnFFPjuOFF/rzyduEVjrVSc+DZfBZziArT0KUkFLM0hhVbE5aqh\n"
        + "Mxw/DPVVxryRCeUcoqmrz16fuRADhh9lCCABfqYrEkpqWFKPXx2by4ka3/D9AgMB\n"
        + "AAGjdDByMAwGA1UdEwEB/wQCMAAwEQYJYIZIAYb4QgEBBAQDAgWgMA4GA1UdDwEB\n"
        + "/wQEAwIDuDAfBgNVHSMEGDAWgBRpUIrgcfG4Hw8bEZUQ9RQMoMA5YTAeBgNVHREB\n"
        + "Af8EFDAShhBodHRwOi8vbXkud2ViLmlkMA0GCSqGSIb3DQEBBQUAA4IBAQCD5A+N\n"
        + "QkKebPVOfr4R+dIM0Wl0/CO96d8oGJud1tmhi6q8KB65xSABbvjhEP3BnitbpQRn\n"
        + "59pyUVmFoNXzSZYAWii+BXVK91DPTJMs1z/0aE22Q6W1vadO7ApvI/9zsimbOZop\n"
        + "aGTDkkWVnqs3O5ZikN9OXf3OYfj7YnsymxInglfaLSNM3ydBa/BGpEpBwjr7woCr\n"
        + "6t4KIaetUgGBaPcsk4uLxreMHtwtByiJXSh1M1p0c55ccE7cXhE6mJp4DoNnKV83\n"
        + "8D3VVMFj6azH/T0CZ4HgcF8FU9jF31RFXStNHNvPin2/uK/4IGgW9uxxOSuVUNO5\n"
        + "a6fwS+1ZnK1gVpFPdXEAfgAEAAAG7qztAAVzcgA4b3JnLnh3aWtpLmNyeXB0by5w\n"
        + "YXNzd2QuaW50ZXJuYWwuQ0FTVDVQYXNzd29yZENpcGhlcnRleHQAAAAAAAAAAQIA\n"
        + "AHhyADtvcmcueHdpa2kuY3J5cHRvLnBhc3N3ZC5pbnRlcm5hbC5BYnN0cmFjdFBh\n"
        + "c3N3b3JkQ2lwaGVydGV4dAAAAAAAAAABAgACWwAKY2lwaGVydGV4dHQAAltCTAAL\n"
        + "a2V5RnVuY3Rpb250AC9Mb3JnL3h3aWtpL2NyeXB0by9wYXNzd2QvS2V5RGVyaXZh\n"
        + "dGlvbkZ1bmN0aW9uO3hwdXIAAltCrPMX+AYIVOACAAB4cAAABMjHtkLQq/DtNecG\n"
        + "6XYQFJIcxNKVZ2qsdgGFlDW9KrLE1yjkvi8e2lclSC9gBEVdeRHRNDRpgQIZzKHG\n"
        + "z4K+17aq03gxZESqznHffTR6I2V7XViWVZoa161SquPv1rPyRboxCXMOBuIs4rQE\n"
        + "wAQbWKzESSsSfDS9Rlxz4rdzMI8pFYQI5m0bk8Y5mMK1LSMW1qMy+qnT7nEZqPXs\n"
        + "uvZPyFeDSm/KYZx1OOII2tBlTms8TGzQPVuZoFIGsOREcxFpFeur/zLTcM4kgpFS\n"
        + "WpZecbOnU/Kbn4LZ6hPooL2JIzbIv0IIy06d4Edow1s7iQsbZTq8VXJ6C6D4dunH\n"
        + "tpJAt2M/o8O2DT5hAy44vcsJuPNksPc5FyoOva4o4MI+Mg0zozBcUZNmf1yaBhFl\n"
        + "jHoxMOw6j0UFIh7B60zF0YKsehtA5dm3wz7X23nkhLfsRBzAgEAUpYkduOj8Am7i\n"
        + "EGT21MEXrSmnLns37ip5zoRdWhF9bk5lTfFtQFe+KCu3PgzxtXSL4L76zMBImWyg\n"
        + "ZPB5MZJzkFwqiJaMrG8IdnN4lfB+/Y/m3UYGAny9vwLFygqAxVK2TwTI/WxGWxd/\n"
        + "rW8cUlttiJ6Kq5G+dDO9RozRGpOBRwmguvz4gL7tZtyufPLjqZteY22KUSB5CZHh\n"
        + "reLY/1g9QsYPdwv9GKlfhDEZwqbwfeX2kn+VxpppQNzVVjbqRXPA53M6TN6V/qKy\n"
        + "A1D0HcJMzbS1jJjxnOiVJmGZtsjNMiFtOYWrG60K22DsvwXwNii5BX4V08+itO9G\n"
        + "ddUbmWI9WoNbz5PXGGAxRxSoZY/OfHGDaY/slzsOUPxMgRbr/Wk6NNSQ9Nx88KIn\n"
        + "Ph1Eox/MkngieilGGUeZ/4LJ7vDCRnjOmVK9xEylg2LkXMBsYebctBEpzrVTsMa0\n"
        + "GSvTfwznsWwwfKVsj0TXfrUyoE9NYXrH4Y05KBeZgT2K5pD1Oqk3EMVIeBwV6dpB\n"
        + "RXt+BTUditkgHc+sTsG5TTyVjokmR09+tE1BMPqYZDrkUMHgYdO8ndc6GJGxX3TS\n"
        + "JHrFyBXCwMzKD7Ifu40uFxA71kY9Idq9xtQL5T6C3LBHmnMTz0Js0qeoxwZlxA1W\n"
        + "kOjVlTw8i0SAIzvdSvcOYHIyrqbOcN31Jt4lBtxBwYybh54PM38UoQ1BiVV5HoRl\n"
        + "xSyedRh7NuG+lzcGdzPm98lPIhlKEwubNiG75NRJRKNeGEU9Aa4keG2yjS1eerfF\n"
        + "B2SudjNdzu/a0SAmqu9M80x1xv8/Lia7KVGlY+9Q0xoBvkmjU9+Hi+gFEtsLQ9d0\n"
        + "/PfrhLe7EyULlbJam6+C9Ldx9ulNsFcBF8T5+5mYBVvJmq6k7PmpY/jCBla0zbw6\n"
        + "JWgRGavuqdA3rxO/ZO2emHijY8Rnqb/XTpManwQtGSXNovnhX1gwJI29cP4M+Oqs\n"
        + "RKHmAa5NJGC3w8VzcwlYuaOB/KcQcWsdv4Zen1kFrCKXWqEIwbvGyuyxc0xWEnho\n"
        + "UZufmkxXa4KdwT3eOZZRn7i/gqZwZoaeWaJEsTj2lEYz/FrfSaoiASaLIr1vmey5\n"
        + "NtcMxWhbpLL/x0NkJB/AykSZIMuIKVnNZm/+KQ7ISHuUq5RKx3pf8GDNDGlXahoD\n"
        + "ikoZH2oMoAuqhxjLcD1zcgBGb3JnLnh3aWtpLmNyeXB0by5wYXNzd2QuaW50ZXJu\n"
        + "YWwuU2NyeXB0TWVtb3J5SGFyZEtleURlcml2YXRpb25GdW5jdGlvbgAAAAAAAAAB\n"
        + "AgAFSQAJYmxvY2tTaXplSQAQZGVyaXZlZEtleUxlbmd0aEkADW1lbW9yeUV4cGVu\n"
        + "c2VJABBwcm9jZXNzb3JFeHBlbnNlWwAEc2FsdHEAfgACeHIASG9yZy54d2lraS5j\n"
        + "cnlwdG8ucGFzc3dkLmludGVybmFsLkFic3RyYWN0TWVtb3J5SGFyZEtleURlcml2\n"
        + "YXRpb25GdW5jdGlvbgAAAAAAAAABAgAAeHAAAAAIAAAAGAAABAAAAAABdXEAfgAF\n"
        + "AAAAEH7JH8+3RHLMhzrEpUGdvC10AANSU0E=\n"
        + "-----END XWIKI CERTIFICATE AND PRIVATE KEY-----\n";

    /** Current user name to use. */
    protected final static String USER = "XWiki.Admin";

    /** Serialized signed script */
    protected static final String SIGNED_SCRIPT =
        "Author        : UID=XWiki.Admin\n" +
        "Authority     : UID=XWiki.Admin\n" +
        "Fingerprint   : 942356b9c40a765c73f600036f89b41cdb09a65b\n" +
        "XWikiVersion  : 2.4M2\n" +
        "CreatedOn     : Wednesday, August 4, 2010 12:18:59 PM UTC\n" +
        "Signature     : MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAQAAoIAwggMuMIIC\n" +
        "                FqADAgECAgYBKjphreUwDQYJKoZIhvcNAQEFBQAwHTEbMBkGCgmSJomT8ixkAQEMC1hXaWtpLkFk\n" +
        "                bWluMB4XDTEwMDgwMzIyNTUzNFoXDTExMDgwMzIzNTUzNFowHTEbMBkGCgmSJomT8ixkAQEMC1hX\n" +
        "                aWtpLkFkbWluMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi4xFJfWGJIkg85D2VpMv\n" +
        "                HxiA83py3k11okU74cBffh/4uG09vfTfj8m0Kda8xF9beuJiNME2p2EwVqftCXcJkL5rn4B+EeFz\n" +
        "                S255wAlOA6TQtJFQ9UoCnQy/7uEuKEUgwmhZCds5TqOyNEkS5lGJU0m39ro0LADYIHV4Pmd5U+wA\n" +
        "                ogtXooG29CrE7cgII1DyTruCtHCR7rxuRTTQAiHvdaEZt9OR/erYEwj6kfsJxRT47jhRf688nbhF\n" +
        "                Y61UnPg2XwWc4gK09ClJBSzNIYVWxOWqoTMcPwz1Vca8kQnlHKKpq89en7kQA4YfZQggAX6mKxJK\n" +
        "                alhSj18dm8uJGt/w/QIDAQABo3QwcjAMBgNVHRMBAf8EAjAAMBEGCWCGSAGG+EIBAQQEAwIFoDAO\n" +
        "                BgNVHQ8BAf8EBAMCA7gwHwYDVR0jBBgwFoAUaVCK4HHxuB8PGxGVEPUUDKDAOWEwHgYDVR0RAQH/\n" +
        "                BBQwEoYQaHR0cDovL215LndlYi5pZDANBgkqhkiG9w0BAQUFAAOCAQEAg+QPjUJCnmz1Tn6+EfnS\n" +
        "                DNFpdPwjvenfKBibndbZoYuqvCgeucUgAW744RD9wZ4rW6UEZ+faclFZhaDV80mWAFoovgV1SvdQ\n" +
        "                z0yTLNc/9GhNtkOltb2nTuwKbyP/c7IpmzmaKWhkw5JFlZ6rNzuWYpDfTl39zmH4+2J7MpsSJ4JX\n" +
        "                2i0jTN8nQWvwRqRKQcI6+8KAq+reCiGnrVIBgWj3LJOLi8a3jB7cLQcoiV0odTNadHOeXHBO3F4R\n" +
        "                OpiaeA6DZylfN/A91VTBY+msx/09AmeB4HBfBVPYxd9URV0rTRzbz4p9v7iv+CBoFvbscTkrlVDT\n" +
        "                uWun8EvtWZytYFaRTwAAMYIBrTCCAakCAQEwJzAdMRswGQYKCZImiZPyLGQBAQwLWFdpa2kuQWRt\n" +
        "                aW4CBgEqOmGt5TAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG\n" +
        "                9w0BCQUxDxcNMTAwODA0MTIxODU5WjAjBgkqhkiG9w0BCQQxFgQUDaEkpynIInmGpXq5DjLwntP4\n" +
        "                eLwwDQYJKoZIhvcNAQEBBQAEggEABkvDf2iqnGpbBH1P0LRpcJUYTz7g1aEINGwe32F5yX1j0iXd\n" +
        "                rvLA4uxprpC8wU64PQsVSpRWlOaYxCeh8Tp6FDqAanguIdE9jeO46YW0rjf5Ls5A8pdthKjy4Ywb\n" +
        "                1teuswMPueqeeRPcujxTyC7fF3E25f+z/Nr6CLQBH9BphO9oKAAvQ72Baekm8JG0xoXkRHnwosgN\n" +
        "                ND+9IXfiPcfxps2K6tQnQ/PIWKse2HmXrYAUphFPsk9/7P2feUai2gs5FfQv2bwC46HXJBiRMTDP\n" +
        "                JWLPjjnk4/2tUb48DX/635B07htw4QKeXzN30Rmb9Cby3wnXhYYo12sS60Lja6UwOgAAAAAAAA==\n" +
        "------------------------------------------------------------\n" +
        "{{groovy}}println();{{/groovy}}\n";

    /** The CODE from the signed script above. */
    protected final String CODE = "{{groovy}}println();{{/groovy}}\n";

    /** Cached instance of the test certificate, used by {@link #getTestCert()}. */
    private XWikiX509Certificate cachedCert;

    /** Cached instance of the test key pair, used by {@link #getTestKeyPair()}. */
    private XWikiX509KeyPair cachedKeyPair;

    /** Need to register new fingerprints manually, since {@link UserDocumentUtils} is mocked. */
    private final List<String> userFingerprints = new LinkedList<String>();

    /** Filled by certificate storage matcher. */
    private final List<XWikiX509Certificate> addedCerts = new LinkedList<XWikiX509Certificate>();

    /** Filled by key pair storage matcher. */
    private final List<XWikiX509KeyPair> addedKeys = new LinkedList<XWikiX509KeyPair>();

    /**
     * {@inheritDoc}
     * 
     * @see org.xwiki.test.AbstractMockingComponentTestCase#setUp()
     */
    @Before
    @Override
    public void setUp() throws Exception
    {
        // register BC provider first
        Security.addProvider(new BouncyCastleProvider());
        super.setUp();
    }

    /**
     * {@inheritDoc}
     * 
     * @see org.xwiki.test.AbstractComponentTestCase#registerComponents()
     */
    @Override
    protected void registerComponents() throws Exception
    {
        super.registerComponents();

        // delete previously registered fingerprints
        userFingerprints.clear();

        // storing matcher auto-registers all added certificates
        final StoringMatcher<XWikiX509Certificate> certStore = new StoringMatcher<XWikiX509Certificate>(this.addedCerts, this.userFingerprints);
        final StoringMatcher<XWikiX509KeyPair> keyStore = new StoringMatcher<XWikiX509KeyPair>(this.addedKeys, this.userFingerprints);
        // mock document utils
        final UserDocumentUtils mockUtils = registerMockComponent(UserDocumentUtils.class);
        this.userFingerprints.add(getTestCertFingerprint());
        this.userFingerprints.add(getTestKeyPair().getFingerprint());
        final States cert = getMockery().states("cert").startsAs("not registered");
        getMockery().checking(new Expectations() {{
            allowing(mockUtils).getCurrentUser();
                will(returnValue(USER));
            allowing(mockUtils).getUserDocURL(USER);
                will(returnValue("http://my.id.org/"));
        }});
        // mock storage utils
        final CryptoStorageUtils mockStorage = registerMockComponent(CryptoStorageUtils.class);
        getMockery().checking(new Expectations() {{
            allowing(mockStorage).getCertificateFingerprintsForUser(with(USER));
                will(returnValue(userFingerprints));
            allowing(mockStorage).addKeyPair(with(USER), with(keyStore));
            allowing(mockStorage).getKeyPairFingerprintsForUser(with(USER));
                will(returnValue(userFingerprints));
            allowing(mockStorage).getUserKeyPair(with(USER), with(any(String.class)), with(any(String.class)));
                will(keyStore);
            allowing(mockStorage).getCertificateFingerprintsForUser(with(TRUSTED_DOC));
                will(returnValue(userFingerprints));
            // pretend registering of certificate fingerprints
            allowing(mockStorage).getUserCertificate(with(TRUSTED_DOC), with(any(String.class)));
                when(cert.is("not registered"));
                will(returnValue(null));
            allowing(mockStorage).getUserCertificate(with(TRUSTED_DOC), with(any(String.class)));
                when(cert.is("registered"));
                will(certStore);
            allowing(mockStorage).addCertificate(with(TRUSTED_DOC), with(certStore));
                then(cert.is("registered"));
            allowing(mockStorage).removeFingerprint(with(TRUSTED_DOC), with(any(String.class)));
                will(returnValue(true));
                then(cert.is("not registered"));
        }});
    }

    /**
     * Get the fingerprint of the test certificate. Same as {@link #getTestCert()}.getFingerprint()
     * 
     * @return fingerprint of the test certificate
     */
    protected String getTestCertFingerprint()
    {
        return CERT_FP;
    }

    /**
     * @return the test certificate
     */
    protected synchronized XWikiX509Certificate getTestCert()
    {
        try {
            if (this.cachedCert == null) {
                this.cachedCert = XWikiX509Certificate.fromPEMString(CERT_PEM);
            }
            return this.cachedCert;
        } catch (GeneralSecurityException exception) {
            // should not happen
            throw new RuntimeException(exception);
        }
    }

    /**
     * @return the test key pair
     */
    protected synchronized XWikiX509KeyPair getTestKeyPair()
    {
        try {
            if (this.cachedKeyPair == null) {
                this.cachedKeyPair = DefaultXWikiX509KeyPair.fromBase64String(KP_PEM);
            }
            return this.cachedKeyPair;
        } catch (Exception exception) {
            // should not happen
            throw new RuntimeException(exception);
        }
    }

    /**
     * A custom matcher action that puts all objects it matches into an external list and returns the first object
     * from that list on invocation. Additionally, adds the fingerprint of certificates and key pairs to the given
     * fingerprint list.
     * 
     * @param <T>
     * @version $Id$
     * @since 2.5
     */
    private class StoringMatcher<T> extends BaseMatcher<T> implements Action
    {
        /** Reference to the list where the data is stored. */
        private final List<T> storage;

        /** Reference to the fingerprint list. */
        private final List<String> fingerprints;

        /**
         * Create new {@link AbstractSignedScriptsTest.StoringMatcher}.
         * 
         * @param storage the list where to put the data
         * @param fingerprints the list where to put the fingerprints
         */
        public StoringMatcher(final List<T> storage, final List<String> fingerprints)
        {
            this.storage = storage;
            this.fingerprints = fingerprints;
        }

        /**
         * This implementation puts all passed arguments into the storage list.
         *
         * @param object the object to match
         * @return true if the object was successfully casted to T and stored in the list, false otherwise
         * @see org.hamcrest.Matcher#matches(java.lang.Object)
         */
        @SuppressWarnings("unchecked")
        public boolean matches(Object object)
        {
            if (object instanceof XWikiX509Certificate) {
                this.fingerprints.add(((XWikiX509Certificate) object).getFingerprint());
            } else if (object instanceof XWikiX509KeyPair) {
                this.fingerprints.add(((XWikiX509KeyPair) object).getFingerprint());
            }
            try {
                this.storage.add((T)object);
                return true;
            } catch (ClassCastException ex) {
                return false;
            }
        }

        /**
         * {@inheritDoc}
         * 
         * @see org.hamcrest.SelfDescribing#describeTo(org.hamcrest.Description)
         */
        public void describeTo(Description d)
        {
            d.appendText("STORING MATCHER: " + this.storage);
        }

        /**
         * {@inheritDoc}
         * 
         * @see org.jmock.api.Invokable#invoke(org.jmock.api.Invocation)
         */
        public T invoke(Invocation invocation) throws Throwable
        {
            if (this.storage.isEmpty()) {
                return null;
            }
            return this.storage.get(0);
        }
    }
}

