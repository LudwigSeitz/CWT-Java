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

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;

import se.sics.ace.AccessToken;
import se.sics.ace.Constants;
import se.sics.ace.AceException;
import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.EncryptMessage;
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.MAC0Message;
import COSE.MACMessage;
import COSE.Message;
import COSE.OneKey;
import COSE.Recipient;
import COSE.Sign1Message;
import COSE.SignMessage;
import COSE.Signer;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/**
 * Implements CWTs.
 * 
 * @author Ludwig Seitz
 *
 */
public class CWT implements AccessToken {

	private Map<String, CBORObject> claims;	
	
	/**
	 * Creates a new CWT without a COSE wrapper.
	 * 
	 * @param claims  the map of claims.
	 */
	public CWT(Map<String, CBORObject> claims) {
		this.claims = new HashMap<> (claims);
	}
	
	/**
	 * Parse and validate the COSE wrapper of a CWT.
	 * 
	 * @param COSE_CWT  the raw bytes of the COSE object containing the CWT
	 * @param ctx  the crypto context
	 * @return  the CWT object wrapped by the COSE object
	 * @throws CoseException 
	 * @throws AceException 
 	 *
	 * @throws Exception 
	 */
	public static CWT processCOSE(byte[] COSE_CWT, CwtCryptoCtx ctx) 
			throws CoseException, AceException, Exception {
		Message coseRaw = Message.DecodeFromBytes(COSE_CWT);
		
		if (coseRaw instanceof SignMessage) {
			SignMessage signed = (SignMessage)coseRaw;
			//Check all signers, if kid is present compare that first
			CBORObject myKid = ctx.getPublicKey().get(
					CBORObject.FromObject(HeaderKeys.KID));
			for (Signer s : signed.getSignerList()) {
				CBORObject kid = s.findAttribute(HeaderKeys.KID);
				if (myKid == null || myKid.equals(kid)) {
					s.setKey(ctx.getPublicKey());
					if(signed.validate(s)) {
						return new CWT(parseClaims(
								CBORObject.DecodeFromBytes(
										signed.GetContent())));
					}
				}
			}
			throw new AceException("No valid signature found");	
			
		} else if (coseRaw instanceof Sign1Message) {
			Sign1Message signed = (Sign1Message)coseRaw;
			if (signed.validate(ctx.getPublicKey())) {
				return new CWT(parseClaims(
					CBORObject.DecodeFromBytes(signed.GetContent())));
			}
			
		} else if (coseRaw instanceof MACMessage) {
			MACMessage maced = (MACMessage)coseRaw;
			for (Recipient me : ctx.getRecipients()) {
				CBORObject myKid = me.findAttribute(HeaderKeys.KID);
				CBORObject myAlg = me.findAttribute(HeaderKeys.Algorithm);
				CBORObject key = CBORObject.NewMap();
				key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
				key.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(
		        		me.getKey(AlgorithmID.FromCBOR(myAlg))));
				for (Recipient r : maced.getRecipientList()) {
					if (myKid == null || myKid.equals(
							r.findAttribute(HeaderKeys.KID)))	{
						if (myAlg.equals(r.findAttribute(HeaderKeys.Algorithm))) {
						    OneKey coseKey = new OneKey(key);
						    r.SetKey(coseKey);			    
						    if (maced.Validate(r)) {
						        return new CWT(parseClaims(
						                CBORObject.DecodeFromBytes(maced.GetContent())));
						    }
						}
					}
				}
			}
			throw new AceException("No valid MAC found");
			
		} else if (coseRaw instanceof MAC0Message) {
			MAC0Message maced = (MAC0Message)coseRaw;
			if (maced.Validate(ctx.getKey())) {
				return new CWT(parseClaims(
						CBORObject.DecodeFromBytes(maced.GetContent())));
			}
			
		} else if (coseRaw instanceof EncryptMessage) {
			EncryptMessage encrypted = (EncryptMessage)coseRaw;
			for (Recipient me : ctx.getRecipients()) {
				CBORObject myKid = me.findAttribute(HeaderKeys.KID);
				CBORObject myAlg = me.findAttribute(HeaderKeys.Algorithm);
				CBORObject key = CBORObject.NewMap();
				key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
				key.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(
		        		me.getKey(AlgorithmID.FromCBOR(myAlg))));
				for (Recipient r : encrypted.getRecipientList()) {
					if (myKid == null || myKid.equals(
							r.findAttribute(HeaderKeys.KID)))	{
						if (myAlg.equals(r.findAttribute(HeaderKeys.Algorithm))) {
						    OneKey coseKey = new OneKey(key);
							r.SetKey(coseKey);
							byte[] plaintext = processDecrypt(encrypted, r);
							if (plaintext != null) {
								return new CWT(parseClaims(
										CBORObject.DecodeFromBytes(
												plaintext)));
							}
						}
					}
				}
			}
			throw new AceException("No valid key for ciphertext found");
			
		} else if (coseRaw instanceof Encrypt0Message) {
			Encrypt0Message encrypted = (Encrypt0Message)coseRaw;
			return new CWT(parseClaims(
					CBORObject.DecodeFromBytes(encrypted.decrypt(
							ctx.getKey()))));
		}
		throw new AceException("Unknown or invalid COSE crypto wrapper");
	}
	
	private static byte[] processDecrypt(EncryptMessage m, Recipient r) {
		try {
			return m.decrypt(r);
		} catch (CoseException e) {
		    e.printStackTrace();
			return null;
		} catch (InvalidCipherTextException e) {
		    e.printStackTrace();
			return null;
		}
	}
	
	
	/**
	 * Process a CBORObject containing a Map of claims.
	 * 
	 * @param content  the CBOR Map of claims
	 * @return  the mapping of unabbreviated claim names to values.
	 * @throws AceException
	 */
	public static Map<String, CBORObject> parseClaims(CBORObject content) 
				throws AceException {
		if (content.getType() != CBORType.Map) {
			throw new AceException("This is not a CWT");
		}
		Map<String, CBORObject> claims = new HashMap<>();
		for (CBORObject key : content.getKeys()) {
			switch(key.getType()) {
			
				case TextString :
					claims.put(key.AsString(), content.get(key));						
					break;
					
				case Number :
					int abbrev = key.AsInt32();
					if (abbrev < Constants.ABBREV.length) {
						claims.put(Constants.ABBREV[abbrev], 
								content.get(key));
					} else {
						throw new AceException(
								"Unknown claim abbreviation: " + abbrev);
					}
					break;
					
				default :
					throw new AceException(
							"Invalid key type in CWT claims map");
			
			}
		}
		return claims;
	}
	
	/**
	 * Encodes this CWT as CBOR Map without crypto wrapper.
	 * 
	 * @return  the claims as CBOR Map.
	 */
	@Override
	public CBORObject encode() {
        return Constants.abbreviate(this.claims);
	}
	
	/**
	 * Encodes this CWT with a COSE crypto wrapper.
	 *
	 * @param ctx  the crypto context.
	 * @return  the claims as CBOR Map.
	 * @throws CoseException 
	 * @throws InvalidCipherTextException 
	 * @throws IllegalStateException 
	 * @throws AceException 
	 * @throws Exception 
	 */
	public CBORObject encode(CwtCryptoCtx ctx) 
	        throws IllegalStateException, InvalidCipherTextException, 
	               CoseException, AceException {
		CBORObject map = encode();
		switch (ctx.getMessageType()) {
		
		case Encrypt0:
			Encrypt0Message coseE0 = new Encrypt0Message();
			coseE0.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
					Attribute.PROTECTED);
			coseE0.SetContent(map.EncodeToBytes());
			coseE0.encrypt(ctx.getKey());
			return coseE0.EncodeToCBORObject();		
			
		case Encrypt:
			EncryptMessage coseE = new EncryptMessage();
			coseE.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
					Attribute.PROTECTED);
			coseE.SetContent(map.EncodeToBytes());
			for (Recipient r : ctx.getRecipients()) {
				coseE.addRecipient(r);
			}
            try {
                coseE.encrypt();
            } catch (Exception e) {
                //Catching Jim's general "not implemented" exception
                //and casting it to something more useful
               throw new CoseException(e.getMessage());
            }
			return coseE.EncodeToCBORObject();
			
		case Sign1:
			Sign1Message coseS1 = new Sign1Message();
			coseS1.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
						Attribute.PROTECTED);
			coseS1.SetContent(map.EncodeToBytes());
			coseS1.sign(ctx.getPrivateKey());
			return coseS1.EncodeToCBORObject();	
			
		case Sign:
			SignMessage coseS = new SignMessage();
			coseS.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
					Attribute.PROTECTED);
			coseS.SetContent(map.EncodeToBytes());
			for (Signer s : ctx.getSigners()) {
				coseS.AddSigner(s);
			}
			coseS.sign();
			return coseS.EncodeToCBORObject();
			
		case MAC:
			MACMessage coseM = new MACMessage();
			coseM.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
					Attribute.PROTECTED);
			coseM.SetContent(map.EncodeToBytes());
			for (Recipient r : ctx.getRecipients()) {
				coseM.addRecipient(r);
			}
			try {
                coseM.Create();
            } catch (Exception e) {
                //Catching Jim's general "not implemented" exception
                //and casting it to something more useful 
                throw new CoseException(e.getMessage());
            }
			return coseM.EncodeToCBORObject();
			
		case MAC0:
			MAC0Message coseM0 = new MAC0Message();
			coseM0.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
					Attribute.PROTECTED);
			coseM0.SetContent(map.EncodeToBytes());
			coseM0.Create(ctx.getKey());
			return coseM0.EncodeToCBORObject();
			
		default:
			throw new AceException("Unknown COSE wrapper type");
			
		}
	}
	
	
	/**
	 * Returns the value of a claim referenced by name or 
	 * <emph>null</emph> if this claim is not in the CWT.
	 * 
	 * @param name  the name of the claim
	 * @return  the value of the claim or null.
	 */
	public CBORObject getClaim(String name) {
		return this.claims.get(name);
	}
	
	/**
	 * @return  a list of all claims in this CWT.
	 */
	public Set<String> getClaimKeys() {
		return this.claims.keySet();
	}
	
	/**
	 * @return a copy of the claims in this CWT.
	 */
	public Map<String, CBORObject> getClaims() {
	    return new HashMap<>(this.claims);
	}
	
	/**
	 * Checks if the token is valid according to the nbf and exp claims
	 * (if present).  Does not check the crypto wrapper.
	 * 
	 * @param now  the current time in ms since January 1, 1970, 00:00:00 GMT
	 * @return  true if the CWT is valid, false if not
	 */
	@Override
	public boolean isValid(long now) {
		//Check nbf and exp for the found match
		CBORObject nbfO = this.claims.get("nbf");
		if (nbfO != null &&  nbfO.AsInt64()	> now) {
			return false;
		}	
		CBORObject expO = this.claims.get("exp");
		if (expO != null && expO.AsInt64() < now) {
			//Token has expired
			return false;
		}
		return true;
	}
	
	/**
	 * Checks if the token is not expired according to the exp claim
	 * (if present).  Does not check anything else.
	 *  
	 * @param now  the current time in ms since January 1, 1970, 00:00:00 GMT
	 * @return  true if the CWT is expired false if it is still valid or has no expiration date
	 */
	@Override
	public boolean expired(long now) {
		CBORObject expO = this.claims.get("exp");
		if (expO != null && expO.AsInt64() < now) {
			//Token has expired
			return true;
		}
		return false;		
	}
	
	@Override
	public String toString() {
	    return this.claims.toString();
	}

    @Override
    public String getCti() throws AceException {
        CBORObject cti = this.claims.get("cti");
        if (cti == null) {
            throw new AceException("Token has no cti");
        }
        return new String(cti.GetByteString());
    }
	
}
