/*******************************************************************************
 * Copyright (c) 2016, SICS Swedish ICT AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package se.sics.ace.cwt;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.CoseException;
import COSE.OneKey;
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.Recipient;
import COSE.Signer;

/**
 * Tests of CWT code
 * 
 * @author Ludwig Seitz
 *
 */
public class CwtTest {
	
    static OneKey publicKey;
    static OneKey privateKey;

    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] key256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};

    static Map<String, CBORObject> claims;
   
    /**
     * Tests for CWT code.
     */
    public CwtTest() {
    }
    
    /**
     * Set up tests.
     * @throws CoseException 
     */
    @BeforeClass
    public static void setUp() throws CoseException {

        privateKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        publicKey = privateKey.PublicKey();

        claims = new HashMap<>();
        claims.put("iss", CBORObject.FromObject("coap://as.example.com"));
        claims.put("aud", CBORObject.FromObject("coap://light.example.com"));
        claims.put("sub", CBORObject.FromObject("erikw"));
        claims.put("exp", CBORObject.FromObject(1444064944));
        claims.put("nbf", CBORObject.FromObject(1443944944));
        claims.put("iat", CBORObject.FromObject(1443944944));
        byte[] cti = {0x0B, 0x71};
        claims.put("cti", CBORObject.FromObject(cti));
        claims.put("cks", 
                CBORObject.DecodeFromBytes(publicKey.EncodeToBytes()));
        claims.put("scope", CBORObject.FromObject(
        		"r+/s/light rwx+/a/led w+/dtls"));
    }

    /**
     * 
     */
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    /**
     * Test of Signed CWT for single recipient.
     * @throws Exception 
     */
    @Test
    public void testRoundTripSign1() throws Exception {
        System.out.println("Round Trip Sign1");
        
        CBORObject alg = AlgorithmID.ECDSA_256.AsCBOR();
        CwtCryptoCtx ctx = CwtCryptoCtx.sign1Create(privateKey, alg);    
        
        CWT cwt = new CWT(claims);
        
        CBORObject msg = cwt.encode(ctx);
        
        byte[] rawCWT = msg.EncodeToBytes();
        ctx = CwtCryptoCtx.sign1Verify(publicKey, alg);
        CWT cwt2 = CWT.processCOSE(rawCWT, ctx);
        
        for (String key : claims.keySet()) {
        	assert(cwt2.getClaimKeys().contains(key));
        }
    }
    
    /**
     * Test of Encrypted CWT for single recipient.
     * @throws Exception 
     */ @Test
     public void testRoundTripEncrypt0() throws Exception {
         System.out.println("Round Trip Encrypt0");
         CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, AlgorithmID.AES_CCM_16_64_128.AsCBOR());
         CWT cwt = new CWT(claims);
         
         CBORObject msg = cwt.encode(ctx);
         
         byte[] rawCWT = msg.EncodeToBytes();
         
        CWT cwt2 = CWT.processCOSE(rawCWT, ctx);
        
         for (String key : claims.keySet()) {
         	assert(cwt2.getClaimKeys().contains(key));
         }
     }
     
     /**
      * Test of MACed CWT for single recipient.
     * @throws Exception 
      */ @Test
      public void testRoundTripMAC0() throws Exception {
          System.out.println("Round Trip MAC0");
          CwtCryptoCtx ctx = CwtCryptoCtx.mac0(key256, AlgorithmID.HMAC_SHA_256_64.AsCBOR());
          CWT cwt = new CWT(claims);
          
         CBORObject msg = cwt.encode(ctx);
          
          byte[] rawCWT = msg.EncodeToBytes();
          
         CWT cwt2 = CWT.processCOSE(rawCWT, ctx);
         
          for (String key : claims.keySet()) {
          	assert(cwt2.getClaimKeys().contains(key));
          }
      }
      
      /**
       * Test of Signed CWT for multiple recipients.
     * @throws Exception 
       */ @Test
       public void testRoundTripSign() throws Exception {
           System.out.println("Round Trip Sign");
           Signer me = new Signer();
           me.setKey(privateKey);
           me.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), 
        		   Attribute.PROTECTED);
           CwtCryptoCtx ctx = CwtCryptoCtx.signCreate(
        		   Collections.singletonList(me), AlgorithmID.ECDSA_256.AsCBOR());
           CWT cwt = new CWT(claims);
           
           CBORObject msg = cwt.encode(ctx);
           
           CwtCryptoCtx ctx2 = CwtCryptoCtx.signVerify(publicKey, AlgorithmID.ECDSA_256.AsCBOR());  
           byte[] rawCWT = msg.EncodeToBytes();
          
           CWT cwt2 = CWT.processCOSE(rawCWT, ctx2);
           
            for (String key : claims.keySet()) {
            	assert(cwt2.getClaimKeys().contains(key));
            }
       }
       
       /**
        * Test of Encrypted CWT for multiple recipients.
        * @throws Exception 
        */ @Test
        public void testRoundTripEncrypt() throws Exception {
            System.out.println("Round Trip Encrypt");
            Recipient me = new Recipient();  
            me.addAttribute(HeaderKeys.Algorithm, 
           		 AlgorithmID.Direct.AsCBOR(), Attribute.UNPROTECTED);
            CBORObject ckey256 = CBORObject.NewMap();
            ckey256.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
            ckey256.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128));
            OneKey cborKey = new OneKey(ckey256);
            me.SetKey(cborKey); 
            CwtCryptoCtx ctx = CwtCryptoCtx.encrypt(
            		Collections.singletonList(me), AlgorithmID.AES_CCM_16_64_128.AsCBOR());  
            CWT cwt = new CWT(claims);
            
            CBORObject msg = cwt.encode(ctx);
            
            CWT cwt2 = CWT.processCOSE(msg.EncodeToBytes(), ctx);
            
            for (String key : claims.keySet()) {
            	assert(cwt2.getClaimKeys().contains(key));
            }
        }
        
        /**
         * Test of MACed CWT for multiple recipients.
         * @throws Exception 
         */ @Test
         public void testRoundTripMAC() throws Exception {
             System.out.println("Round Trip MAC");
             Recipient me = new Recipient();  
             me.addAttribute(HeaderKeys.Algorithm, 
            		 AlgorithmID.Direct.AsCBOR(), Attribute.UNPROTECTED);
             CBORObject ckey256 = CBORObject.NewMap();
             ckey256.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
             ckey256.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key256));
             OneKey cborKey = new OneKey(ckey256);
             me.SetKey(cborKey); 
             CwtCryptoCtx ctx = CwtCryptoCtx.mac (
            		 Collections.singletonList(me), AlgorithmID.HMAC_SHA_256.AsCBOR());  
             CWT cwt = new CWT(claims);
             
             CBORObject msg = cwt.encode(ctx);
             
             CWT cwt2 = CWT.processCOSE(msg.EncodeToBytes(), ctx);
             
             for (String key : claims.keySet()) {
             	assert(cwt2.getClaimKeys().contains(key));
             }
         }

         /**
          * Test of the isValid() method.
          * @throws Exception
          */ @Test
         public void testValid() throws Exception {
        	 System.out.println("Test isValid() method");
        	 CWT cwt = new CWT(CwtTest.claims);
        	 long early = 1443944942;
        	 long late = 1444064948;
        	 long now = 1444064928;
        	 assert(!cwt.isValid(early));
        	 assert(!cwt.isValid(late));
        	 assert(cwt.isValid(now));        	 
         }

          /**
           * Test of the expired() method.
           * @throws Exception
           */ @Test
           public void testExpired() throws Exception {
        	   System.out.println("Test expired() method");
        	   CWT cwt = new CWT(CwtTest.claims);
        	   long early = 1443944942;
        	   long late = 1444064948;
        	   long now = 1444064928;
        	   assert(!cwt.expired(early));
        	   assert(cwt.expired(late));
        	   assert(!cwt.expired(now));        	 
           }
}
