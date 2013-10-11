/**
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */
package com.joyent.manta.client.crypto;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Base64;

import com.google.api.client.http.HttpRequest;
import com.joyent.manta.exception.MantaCryptoException;

/**
 * Joyent HTTP authorization signer. This adheres to the specs of the node-http-signature spec.
 *
 * @author Yunong Xiao
 * @author Bill Headrick
 */
public class HttpSigner {
    private static final Log LOG = LogFactory.getLog(HttpSigner.class);
    private static final DateFormat DATE_FORMAT = new SimpleDateFormat("EEE MMM d HH:mm:ss yyyy zzz");
    private static final String AUTHZ_HEADER = "Signature keyId=\"/%s/keys/%s\",algorithm=\"rsa-sha256\","
        + "signature=\"%s\"";
    private static final String AUTHZ_SIGNING_STRING = "date: %s";
    private static final String AUTHZ_PATTERN = "signature=\"";
    static final String SIGNING_ALGORITHM = "SHA256WithRSAEncryption";

    /**
     * Returns a new {@link HttpSigner} instance that can be used to sign and verify requests according to the
     * joyent-http-signature spec.
     *
     * @see <a href="http://github.com/joyent/node-http-signature/blob/master/http_signing.md">node-http-signature</a>
     * @param keyPath
     *            The path to the rsa key on disk.
     * @param fingerPrint
     *            (optional) The fingerprint of the rsa key.  If the keyPath is a valid RSA key, the fingerprint will be
     *            calculated from the public part of the Key.
     * @param login
     *            The login of the user account.
     * @return An instance of {@link HttpSigner}.
     * @throws IOException
     *             If the key is invalid.
     */
    public static final HttpSigner newInstance(String keyPath, String fingerPrint, String login) throws IOException {
        return new HttpSigner(keyPath, fingerPrint, login);
    }

    private KeyPair keyPair_;
    private final String login_;

    private String fingerPrint_;

    /**
     * @param keyPath
     * @param fingerprint
     * @param login
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    private HttpSigner(String keyPath, String fingerprint, String login) throws IOException {
        LOG.debug(String.format("initializing HttpSigner with keypath: %s, fingerprint: %s, login: %s", keyPath, fingerprint, login));
        fingerPrint_ = fingerprint;
        login_ = login;
        updateKeyPair(keyPath);
    }

    /**
     * Update the KeyPair (and possibly the fingerprint) for the signer.
     *
     * @param keyPath
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private void updateKeyPair(String keyPath) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(keyPath));
        Security.addProvider(new BouncyCastleProvider());
        PEMReader pemReader = new PEMReader(br);
        KeyPair kp = (KeyPair) pemReader.readObject();
        pemReader.close();

        PublicKey publicKey = kp.getPublic();
        // If the key is RSA, calculate the fingerprint of the public key.
        if (publicKey.getAlgorithm().equalsIgnoreCase("RSA")) {
            // Calculate the fingerprint for the public key...
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeInt("ssh-rsa".getBytes().length);
            dos.write("ssh-rsa".getBytes());

            byte[] publicExponent = rsaPublicKey.getPublicExponent().toByteArray();
            byte[] modulus = rsaPublicKey.getModulus().toByteArray();

            dos.writeInt(publicExponent.length);
            dos.write(publicExponent);
            dos.writeInt(modulus.length);
            dos.write(modulus);

            byte [] barr = baos.toByteArray();
            String calculatedFingerprint1 = getFingerprint(barr);
            LOG.debug("Calculated Fingerprint " + calculatedFingerprint1);
            fingerPrint_ = calculatedFingerprint1;
        }

        keyPair_ = kp;
    }

    private String getFingerprint(byte[] barr) {
        String digestAlgName = "MD5";
        MessageDigest alg = null;
        try {
            alg = MessageDigest.getInstance(digestAlgName);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("invalid signature digest algorithm: " + digestAlgName, e);
        }
        byte[] digest = alg.digest(barr);
        String hx = getHexString(digest, ":");
        return hx;
    }
    private static final char[] hexChar = {
        '0' , '1' , '2' , '3' ,
        '4' , '5' , '6' , '7' ,
        '8' , '9' , 'a' , 'b' ,
        'c' , 'd' , 'e' , 'f'
    };

    private static String getHexString(byte[] barr, String separator) {
        return getHexString(barr, separator, 0, barr.length);
    }
    private static String getHexString(byte[] barr, String separator, int startIdx, int length) {
        if (null == barr || 0 == length) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int start = startIdx;
        int end = startIdx + length;
        for (int i=start; i<end; i++) {
            if (null != separator && i != start) {
                sb.append(separator);
            }
            // look up high char
            sb.append(hexChar[(barr[i] & 0xf0) >>> 4]); // fill left with zero bits

            // look up low char
            sb.append(hexChar[barr[i] & 0x0f]);
        }
        return sb.toString();
    }
    /**
     * Sign an {@link HttpRequest}.
     *
     * @param request
     *            The {@link HttpRequest} to sign.
     * @throws MantaCryptoException
     *             If unable to sign the request.
     */
    public final void signRequest(HttpRequest request) throws MantaCryptoException {
        LOG.debug("signing request: " + request.getHeaders());
        String date = request.getHeaders().getDate();
        if (date == null) {
            Date now = Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTime();
            date = DATE_FORMAT.format(now);
            LOG.debug("setting date header: " + date);
            request.getHeaders().setDate(date);
        }
        try {
            Signature sig = Signature.getInstance(SIGNING_ALGORITHM);
            sig.initSign(keyPair_.getPrivate());
            String signingString = String.format(AUTHZ_SIGNING_STRING, date);
            sig.update(signingString.getBytes("UTF-8"));
            byte[] signedDate = sig.sign();
            byte[] encodedSignedDate = Base64.encode(signedDate);
            String authzHeader = String.format(AUTHZ_HEADER, login_, fingerPrint_, new String(encodedSignedDate));
            request.getHeaders().setAuthorization(authzHeader);
        } catch (NoSuchAlgorithmException e) {
            throw new MantaCryptoException("invalid algorithm", e);
        } catch (InvalidKeyException e) {
            throw new MantaCryptoException("invalid key", e);
        } catch (SignatureException e) {
            throw new MantaCryptoException("invalid signature", e);
        } catch (UnsupportedEncodingException e) {
            throw new MantaCryptoException("invalid encoding", e);
        }
    }

    /**
     * Verify a signed {@link HttpRequest}.
     *
     * @param request
     *            The signed {@link HttpRequest}.
     * @return True if the request is valid, false if not.
     * @throws MantaCryptoException
     *             If unable to verify the request.
     */
    public final boolean verifyRequest(HttpRequest request) throws MantaCryptoException {
        LOG.debug("verifying request: " + request.getHeaders());
        String date = request.getHeaders().getDate();
        if (date == null) {
            throw new MantaCryptoException("no date header in request");
        }

        date = String.format(AUTHZ_SIGNING_STRING, date);

        try {
            Signature verify = Signature.getInstance(SIGNING_ALGORITHM);
            verify.initVerify(keyPair_.getPublic());
            String authzHeader = request.getHeaders().getAuthorization();
            int startIndex = authzHeader.indexOf(AUTHZ_PATTERN);
            if (startIndex == -1) {
                throw new MantaCryptoException("invalid authorization header " + authzHeader);
            }
            String encodedSignedDate = authzHeader.substring(startIndex + AUTHZ_PATTERN.length(),
                                                             authzHeader.length() - 1);
            byte[] signedDate = Base64.decode(encodedSignedDate.getBytes("UTF-8"));
            verify.update(date.getBytes("UTF-8"));
            return verify.verify(signedDate);
        } catch (NoSuchAlgorithmException e) {
            throw new MantaCryptoException("invalid algorithm", e);
        } catch (InvalidKeyException e) {
            throw new MantaCryptoException("invalid key", e);
        } catch (SignatureException e) {
            throw new MantaCryptoException("invalid signature", e);
        } catch (UnsupportedEncodingException e) {
            throw new MantaCryptoException("invalid encoding", e);
        }
    }
}
