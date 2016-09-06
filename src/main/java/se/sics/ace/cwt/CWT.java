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

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;

import se.sics.ace.Constants;

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
import COSE.MessageTag;
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
public class CWT {

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
	 * @throws CWTException 
 	 *
	 * @throws Exception 
	 */
	public static CWT processCOSE(byte[] COSE_CWT, CwtCryptoCtx ctx) 
			throws CoseException, CWTException, Exception {
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
			throw new CWTException("No valid signature found");	
			
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
							r.SetKey(key);
							if (maced.Validate(r)) {
								return new CWT(parseClaims(
										CBORObject.DecodeFromBytes(maced.GetContent())));
							}
						}
					}
				}
			}
			throw new CWTException("No valid MAC found");
			
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
							r.SetKey(key);
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
			throw new CWTException("No valid key for ciphertext found");
			
		} else if (coseRaw instanceof Encrypt0Message) {
			Encrypt0Message encrypted = (Encrypt0Message)coseRaw;
			return new CWT(parseClaims(
					CBORObject.DecodeFromBytes(encrypted.decrypt(
							ctx.getKey()))));
		}
		throw new CWTException("Unknown or invalid COSE crypto wrapper");
	}
	
	private static byte[] processDecrypt(EncryptMessage m, Recipient r) {
		try {
			return m.decrypt(r);
		} catch (CoseException e) {
			return null;
		} catch (InvalidCipherTextException e) {
			return null;
		}
	}
	
	
	/**
	 * Process a CBORObject containing a Map of claims.
	 * 
	 * @param content  the CBOR Map of claims
	 * @return  the mapping of unabbreviated claim names to values.
	 * @throws CWTException
	 */
	public static Map<String, CBORObject> parseClaims(CBORObject content) 
				throws CWTException {
		if (content.getType() != CBORType.Map) {
			throw new CWTException("This is not a CWT");
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
						throw new CWTException(
								"Unknown claim abbreviation: " + abbrev);
					}
					break;
					
				default :
					throw new CWTException(
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
	public CBORObject encode() {
		CBORObject map = CBORObject.NewMap();
		for (String key : this.claims.keySet()) {
			short i = Constants.getAbbrev(key);
			if (i != -1) {
				map.Add(CBORObject.FromObject(i), this.claims.get(key));
			} else { //This claim/parameter has no abbreviation
				map.Add(CBORObject.FromObject(key), this.claims.get(key));
			}
		}
		return map;
	}
	
	/**
	 * Encodes this CWT with a COSE crypto wrapper.
	 * 
	 * @param what  the type of COSE wrapper to add.
	 * @param ctx  the crypto context.
	 * @return  the claims as CBOR Map.
	 * @throws Exception 
	 */
	public Message encode(MessageTag what, CwtCryptoCtx ctx) 
			throws Exception {
		CBORObject map = encode();
		switch (what) {
		
		case Encrypt0:
			Encrypt0Message coseE0 = new Encrypt0Message();
			coseE0.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
					Attribute.ProtectedAttributes);
			coseE0.SetContent(map.EncodeToBytes());
			coseE0.encrypt(ctx.getKey());
			return coseE0;		
			
		case Encrypt:
			EncryptMessage coseE = new EncryptMessage();
			coseE.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
					Attribute.ProtectedAttributes);
			coseE.SetContent(map.EncodeToBytes());
			for (Recipient r : ctx.getRecipients()) {
				coseE.addRecipient(r);
			}
			coseE.encrypt();
			return coseE;
			
		case Sign1:
			Sign1Message coseS1 = new Sign1Message();
			coseS1.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
						Attribute.ProtectedAttributes);
			coseS1.SetContent(map.EncodeToBytes());
			coseS1.sign(ctx.getPrivateKey());
			return coseS1;	
			
		case Sign:
			SignMessage coseS = new SignMessage();
			coseS.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
					Attribute.ProtectedAttributes);
			coseS.SetContent(map.EncodeToBytes());
			for (Signer s : ctx.getSigners()) {
				coseS.AddSigner(s);
			}
			coseS.sign();
			return coseS;
			
		case MAC:
			MACMessage coseM = new MACMessage();
			coseM.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
					Attribute.ProtectedAttributes);
			coseM.SetContent(map.EncodeToBytes());
			for (Recipient r : ctx.getRecipients()) {
				coseM.addRecipient(r);
			}
			coseM.Create();
			return coseM;
			
		case MAC0:
			MAC0Message coseM0 = new MAC0Message();
			coseM0.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
					Attribute.ProtectedAttributes);
			coseM0.SetContent(map.EncodeToBytes());
			coseM0.Create(ctx.getKey());
			return coseM0;
			
		default:
			throw new CWTException("Unknown COSE wrapper type");
			
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
	 * Checks if the token is valid according to the nbf and exp claims
	 * (if present).  Does not check the crypto wrapper.
	 * 
	 * @param now  the current time in ms since January 1, 1970, 00:00:00 GMT
	 * @return  true if the CWT is valid, false if not
	 */
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
	public boolean expired(long now) {
		CBORObject expO = this.claims.get("exp");
		if (expO != null && expO.AsInt64() < now) {
			//Token has expired
			return true;
		}
		return false;		
	}
	
}
