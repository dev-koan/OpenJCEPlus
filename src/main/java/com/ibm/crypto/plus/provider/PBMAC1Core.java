/*
 * Copyright (c) 2003, 2024, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.ibm.crypto.plus.provider;

import java.util.Arrays;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.*;
import java.security.MessageDigest;

/**
 * This is an implementation of the PBMAC1 algorithms as defined
 * in PKCS#5 v2.1 standard.
 */
public class PBMAC1Core extends MacSpi {
    // NOTE: this class inherits the Cloneable interface from HmacCore
    // Need to override clone() if mutable fields are added.
    private final String kdfAlgo;
    private final String hashAlgo;
    private final int blockLength; // in octets
    private final OpenJCEPlusProvider provider;

    private MessageDigest md;
    private byte[] k_ipad; // inner padding - key XORd with ipad
    private byte[] k_opad; // outer padding - key XORd with opad
    private boolean first;       // Is this the first data to be processed?

    private final int blockLen;
    /**
     * Creates an instance of PBMAC1 according to the selected
     * password-based key derivation function.
     */
    PBMAC1Core(String kdfAlgo, String hashAlgo, int blockLength, OpenJCEPlusProvider provider)
        throws NoSuchAlgorithmException {
        this.kdfAlgo = kdfAlgo;
        this.hashAlgo = hashAlgo;
        this.blockLength = blockLength;
        this.provider = provider;

        MessageDigest md = MessageDigest.getInstance(hashAlgo);
                if (!(md instanceof Cloneable)) {
            // use SUN provider if the most preferred one does not support
            // cloning
            Provider sun = Security.getProvider("SUN");
            if (sun != null) {
                md = MessageDigest.getInstance(hashAlgo, sun);
            } else {
                String noCloneProv = md.getProvider().getName();
                // if no Sun provider, use provider list
                md = null;
                Provider[] provs = Security.getProviders();
                for (Provider p : provs) {
                    try {
                        if (!p.getName().equals(noCloneProv)) {
                            MessageDigest md2 =
                                MessageDigest.getInstance(hashAlgo, p);
                            if (md2 instanceof Cloneable) {
                                md = md2;
                                break;
                            }
                        }
                    } catch (NoSuchAlgorithmException ignored) {
                    }
                }
                if (md == null) {
                    throw new NoSuchAlgorithmException
                            ("No Cloneable digest found for " + hashAlgo);
                }
            }
        }
        this.md = md;
        this.blockLen = blockLength;
        this.k_ipad = new byte[blockLen];
        this.k_opad = new byte[blockLen];
        first = true;

    }

    private PBKDF2Core getKDFImpl(String algo) {
        PBKDF2Core kdf;
        switch(algo) {
        case "HmacSHA1":
                kdf = new PBKDF2Core.HmacSHA1(provider);
                break;
        case "HmacSHA224":
                kdf = new PBKDF2Core.HmacSHA224(provider);
                break;
        case "HmacSHA256":
                kdf = new PBKDF2Core.HmacSHA256(provider);
                break;
        case "HmacSHA384":
                kdf = new PBKDF2Core.HmacSHA384(provider);
                break;
        case "HmacSHA512":
                kdf = new PBKDF2Core.HmacSHA512(provider);
                break;
        case "HmacSHA512/224":
                kdf = new PBKDF2Core.HmacSHA512_224(provider);
                break;
        case "HmacSHA512/256":
                kdf = new PBKDF2Core.HmacSHA512_256(provider);
                break;
        default:
                throw new ProviderException(
                    "No MAC implementation for " + algo);
        }
        return kdf;
    }

    /**
     * Initializes the HMAC with the given secret key and algorithm parameters.
     *
     * @param key the secret key.
     * @param params the algorithm parameters.
     *
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this MAC.
     * @exception InvalidAlgorithmParameterException if the given algorithm
     * parameters are inappropriate for this MAC.
     */
    protected void engineInit(Key key, AlgorithmParameterSpec params)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
        char[] passwdChars;
        byte[] salt = null;
        int iCount = 0;
        if (key instanceof javax.crypto.interfaces.PBEKey) {
            javax.crypto.interfaces.PBEKey pbeKey =
                (javax.crypto.interfaces.PBEKey) key;
            passwdChars = pbeKey.getPassword();
            salt = pbeKey.getSalt(); // maybe null if unspecified
            iCount = pbeKey.getIterationCount(); // maybe 0 if unspecified
        } else if (key instanceof SecretKey) {
            byte[] passwdBytes;
            if (!(key.getAlgorithm().regionMatches(true, 0, "PBE", 0, 3)) ||
                    (passwdBytes = key.getEncoded()) == null) {
                throw new InvalidKeyException("Missing password");
            }
            passwdChars = new char[passwdBytes.length];
            for (int i=0; i<passwdChars.length; i++) {
                passwdChars[i] = (char) (passwdBytes[i] & 0x7f);
            }
            Arrays.fill(passwdBytes, (byte)0x00);
        } else {
            throw new InvalidKeyException("SecretKey of PBE type required");
        }

        PBEKeySpec pbeSpec;
        try {
            if (params == null) {
                // should not auto-generate default values since current
                // javax.crypto.Mac api does not have any method for caller to
                // retrieve the generated defaults.
                if ((salt == null) || (iCount == 0)) {
                    throw new InvalidAlgorithmParameterException
                            ("PBEParameterSpec required for salt and iteration count");
                }
            } else if (!(params instanceof PBEParameterSpec)) {
                throw new InvalidAlgorithmParameterException
                        ("PBEParameterSpec type required");
            } else {
                PBEParameterSpec pbeParams = (PBEParameterSpec) params;
                // make sure the parameter values are consistent
                if (salt != null) {
                    if (!Arrays.equals(salt, pbeParams.getSalt())) {
                        throw new InvalidAlgorithmParameterException
                                ("Inconsistent value of salt between key and params");
                    }
                } else {
                    salt = pbeParams.getSalt();
                }
                if (iCount != 0) {
                    if (iCount != pbeParams.getIterationCount()) {
                        throw new InvalidAlgorithmParameterException
                                ("Different iteration count between key and params");
                    }
                } else {
                    iCount = pbeParams.getIterationCount();
                }
            }
            // For security purpose, we need to enforce a minimum length
            // for salt; just require the minimum salt length to be 8-byte
            // which is what PKCS#5 recommends and openssl does.
            if (salt.length < 8) {
                throw new InvalidAlgorithmParameterException
                        ("Salt must be at least 8 bytes long");
            }
            if (iCount <= 0) {
                throw new InvalidAlgorithmParameterException
                        ("IterationCount must be a positive number");
            }

            pbeSpec = new PBEKeySpec(passwdChars, salt, iCount, blockLength);
            // password char[] was cloned in PBEKeySpec constructor,
            // so we can zero it out here
        } finally {
            Arrays.fill(passwdChars, '\0');
        }

        PBKDF2KeyImpl s = null;
        byte[] derivedKey = null;
        SecretKeySpec cipherKey = null;
        try {
            PBKDF2Core kdf = getKDFImpl(kdfAlgo);
            s = (PBKDF2KeyImpl) kdf.engineGenerateSecret(pbeSpec);
            derivedKey = s.getEncoded();
            cipherKey = new SecretKeySpec(derivedKey, kdfAlgo);
            
            if (!(key instanceof SecretKey)) {
                throw new InvalidKeyException("Secret key expected");
            }

            byte[] secret = key.getEncoded();
            if (secret == null) {
                throw new InvalidKeyException("Missing key data");
            }

            // if key is longer than the block length, reset it using
            // the message digest object.
            if (secret.length > blockLen) {
                byte[] tmp = md.digest(secret);
                // now erase the secret
                Arrays.fill(secret, (byte)0);
                secret = tmp;
            }

            // XOR k with ipad and opad, respectively
            for (int i = 0; i < blockLen; i++) {
                int si = (i < secret.length) ? secret[i] : 0;
                k_ipad[i] = (byte)(si ^ 0x36);
                k_opad[i] = (byte)(si ^ 0x5c);
            }

            // now erase the secret
            Arrays.fill(secret, (byte)0);
            secret = null;

            engineReset();
        } catch (InvalidKeySpecException ikse) {
            throw new InvalidKeyException("Cannot construct PBE key", ikse);
        } finally {
            if (cipherKey != null) {
                // SharedSecrets.getJavaxCryptoSpecAccess()
                //         .clearSecretKeySpec(cipherKey);
            }
            if (derivedKey != null) {
                Arrays.fill(derivedKey, (byte) 0x00);
            }
            if (s != null) {
                // s.clear();
            }
            pbeSpec.clearPassword();
        }
    }

        protected void engineUpdate(byte input) {
        if (first) {
            // compute digest for 1st pass; start with inner pad
            md.update(k_ipad);
            first = false;
        }

        // add the passed byte to the inner digest
        md.update(input);
    }

    protected void engineReset() {
        if (!first) {
            md.reset();
            first = true;
        }
    }

    /**
     * Processes the first <code>len</code> bytes in <code>input</code>,
     * starting at <code>offset</code>.
     *
     * @param input the input buffer.
     * @param offset the offset in <code>input</code> where the input starts.
     * @param len the number of bytes to process.
     */
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (first) {
            // compute digest for 1st pass; start with inner pad
            md.update(k_ipad);
            first = false;
        }

        // add the selected part of an array of bytes to the inner digest
        md.update(input, offset, len);
    }

    /**
     * Processes the <code>input.remaining()</code> bytes in the ByteBuffer
     * <code>input</code>.
     *
     * @param input the input byte buffer.
     */
    protected void engineUpdate(ByteBuffer input) {
        if (first) {
            // compute digest for 1st pass; start with inner pad
            md.update(k_ipad);
            first = false;
        }

        md.update(input);
    }

    /**
     * Completes the HMAC computation and resets the HMAC for further use,
     * maintaining the secret key that the HMAC was initialized with.
     *
     * @return the HMAC result.
     */
    protected byte[] engineDoFinal() {
        if (first) {
            // compute digest for 1st pass; start with inner pad
            md.update(k_ipad);
        } else {
            first = true;
        }

        try {
            // finish the inner digest
            byte[] tmp = md.digest();

            // compute digest for 2nd pass; start with outer pad
            md.update(k_opad);
            // add result of 1st hash
            md.update(tmp);

            md.digest(tmp, 0, tmp.length);
            md.reset();
            return tmp;
        } catch (DigestException e) {
            // should never occur
            throw new ProviderException(e);
        }
    }

    protected int engineGetMacLength() {
        return this.md.getDigestLength();
    }

    public static final class HmacSHA1 extends PBMAC1Core {
        public HmacSHA1(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super("HmacSHA1", "SHA1", 64, provider);
        }
    }

    public static final class HmacSHA224 extends PBMAC1Core {
        public HmacSHA224(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super("HmacSHA224", "SHA-224", 64, provider);
        }
    }

    public static final class HmacSHA256 extends PBMAC1Core {
        public HmacSHA256(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super("HmacSHA256", "SHA-256", 64, provider);
        }
    }

    public static final class HmacSHA384 extends PBMAC1Core {
        public HmacSHA384(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super("HmacSHA384", "SHA-384", 128, provider);
        }
    }

    public static final class HmacSHA512 extends PBMAC1Core {
        public HmacSHA512(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super("HmacSHA512", "SHA-512", 128, provider);
        }
    }

    public static final class HmacSHA512_224 extends PBMAC1Core {
        public HmacSHA512_224(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super("HmacSHA512/224", "SHA-512/224", 128, provider);
        }
    }

    public static final class HmacSHA512_256 extends PBMAC1Core {
        public HmacSHA512_256(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super("HmacSHA512/256", "SHA-512/256", 128, provider);
        }
    }
}
