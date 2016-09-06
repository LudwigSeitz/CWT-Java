/*******************************************************************************
 * Copyright 2016 SICS Swedish ICT AB.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *******************************************************************************/
package se.sics.ace.cwt;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.Encrypt0Message;
import COSE.EncryptMessage;
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.MAC0Message;
import COSE.MACMessage;
import COSE.MessageTag;
import COSE.Recipient;
import COSE.Sign1Message;
import COSE.SignMessage;
import COSE.Signer;

import com.upokecenter.cbor.CBORObject;

/**
 * Tests of CWT code
 * 
 * @author Ludwig Seitz
 *
 */
public class CwtTest {
	
    static CBORObject cnKeyPublic;
    static CBORObject cnKeyPublicCompressed;
    static CBORObject cnKeyPrivate;
    static ECPublicKeyParameters keyPublic;
    static ECPrivateKeyParameters keyPrivate;
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
     */
    @BeforeClass
    public static void setUpClass() {
    
        X9ECParameters p = NISTNamedCurves.getByName("P-256");
        
        ECDomainParameters parameters = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        ECKeyPairGenerator pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, null);
        pGen.init(genParam);
        
        AsymmetricCipherKeyPair p1 = pGen.generateKeyPair();
        
        keyPublic = (ECPublicKeyParameters) p1.getPublic();
        keyPrivate = (ECPrivateKeyParameters) p1.getPrivate();
        
        byte[] rgbX = keyPublic.getQ().normalize().getXCoord().getEncoded();
        byte[] rgbY = keyPublic.getQ().normalize().getYCoord().getEncoded();
        byte[] rgbD = keyPrivate.getD().toByteArray();

        cnKeyPublic = CBORObject.NewMap();
        cnKeyPublic.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        cnKeyPublic.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        cnKeyPublic.Add(KeyKeys.EC2_X.AsCBOR(), rgbX);
        cnKeyPublic.Add(KeyKeys.EC2_Y.AsCBOR(), rgbY);
        
        cnKeyPublicCompressed = CBORObject.NewMap();
        cnKeyPublicCompressed.Add(KeyKeys.KeyType.AsCBOR(), 
        			KeyKeys.KeyType_EC2);
        cnKeyPublicCompressed.Add(KeyKeys.EC2_Curve.AsCBOR(), 
        			KeyKeys.EC2_P256);
        cnKeyPublicCompressed.Add(KeyKeys.EC2_X.AsCBOR(), rgbX);
        cnKeyPublicCompressed.Add(KeyKeys.EC2_Y.AsCBOR(), rgbY);

        cnKeyPrivate = CBORObject.NewMap();
        cnKeyPrivate.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        cnKeyPrivate.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        cnKeyPrivate.Add(KeyKeys.EC2_D.AsCBOR(), rgbD);
        
        
               
        claims = new HashMap<String, CBORObject>();
        claims.put("iss", CBORObject.FromObject("coap://as.example.com"));
        claims.put("aud", CBORObject.FromObject("coap://light.example.com"));
        claims.put("sub", CBORObject.FromObject("erikw"));
        claims.put("exp", CBORObject.FromObject(1444064944));
        claims.put("nbf", CBORObject.FromObject(1443944944));
        claims.put("iat", CBORObject.FromObject(1443944944));
        byte[] cti = {0x0B, 0x71};
        claims.put("cti", CBORObject.FromObject(cti));
        claims.put("cks", cnKeyPublic);
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
        CwtCryptoCtx ctx = CwtCryptoCtx.sign1Create(cnKeyPrivate, alg);    
        
        CWT cwt = new CWT(claims);
        
        Sign1Message msg = (Sign1Message)cwt.encode(MessageTag.Sign1, ctx);
        
        byte[] rawCWT = msg.EncodeToBytes();
        
        ctx = CwtCryptoCtx.sign1Verify(cnKeyPublic, alg);
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
         
         Encrypt0Message msg = (Encrypt0Message)cwt.encode(MessageTag.Encrypt0, ctx);
         
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
          
         MAC0Message msg = (MAC0Message)cwt.encode(MessageTag.MAC0, ctx);
          
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
           me.setKey(cnKeyPrivate);
           me.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), 
        		   Attribute.ProtectedAttributes);
           CwtCryptoCtx ctx = CwtCryptoCtx.signCreate(
        		   Collections.singletonList(me), AlgorithmID.ECDSA_256.AsCBOR());
           CWT cwt = new CWT(claims);
           
           SignMessage msg = (SignMessage)cwt.encode(MessageTag.Sign, ctx);
           
           CwtCryptoCtx ctx2 = CwtCryptoCtx.signVerify(cnKeyPublic, AlgorithmID.ECDSA_256.AsCBOR());  
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
           		 AlgorithmID.Direct.AsCBOR(), Attribute.UnprotectedAttributes);
            CBORObject ckey256 = CBORObject.NewMap();
            ckey256.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
            ckey256.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128));
            me.SetKey(ckey256); 
            CwtCryptoCtx ctx = CwtCryptoCtx.encrypt(
            		Collections.singletonList(me), AlgorithmID.AES_CCM_16_64_128.AsCBOR());  
            CWT cwt = new CWT(claims);
            
            EncryptMessage msg = (EncryptMessage)cwt.encode(MessageTag.Encrypt, ctx);
            
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
            		 AlgorithmID.Direct.AsCBOR(), Attribute.UnprotectedAttributes);
             CBORObject ckey256 = CBORObject.NewMap();
             ckey256.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
             ckey256.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key256));
             me.SetKey(ckey256); 
             CwtCryptoCtx ctx = CwtCryptoCtx.mac (
            		 Collections.singletonList(me), AlgorithmID.HMAC_SHA_256.AsCBOR());  
             CWT cwt = new CWT(claims);
             
             MACMessage msg = (MACMessage)cwt.encode(MessageTag.MAC, ctx);
             
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
