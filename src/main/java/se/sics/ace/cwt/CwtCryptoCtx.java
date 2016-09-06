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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.upokecenter.cbor.CBORObject;

import COSE.Recipient;
import COSE.Signer;

/**
 * This class holds the singing/mac-ing/encrypting context for a CWT or COSE message.
 * 
 * Instead of a constructor, use the static methods, which give you an indication
 * what parameters are expected for the different COSE message types.
 * 
 * @author Ludwig Seitz
 *
 */
public class CwtCryptoCtx {

	private List<Signer> signers = Collections.emptyList();
	
	private CBORObject privatekey = null;
	
	private List<Recipient> recipients = Collections.emptyList();
	
	private byte[] rawSymmetricKey = null;

	private CBORObject publicKey = null;
	
	private CBORObject alg = null;
	
	protected CwtCryptoCtx(byte[] key, CBORObject alg) {
		this.rawSymmetricKey = key;
		this.alg = alg;
	}
	
	protected CwtCryptoCtx(CBORObject publicKey, CBORObject privateKey, CBORObject alg) {
		this.publicKey = publicKey;
		this.privatekey = privateKey;
		this.alg = alg;
	}

	protected CwtCryptoCtx(List<Recipient> recipients, CBORObject alg) {
		this.recipients = new ArrayList<>();
		this.recipients.addAll(recipients);
		this.alg = alg;
	}

	
	protected CwtCryptoCtx(List<Signer> signers, CBORObject alg, boolean sign) {
		this.signers = new ArrayList<>();
		this.signers.addAll(signers);
		this.alg = alg;
		if (sign) {//Do nothing, this is needed so this constructor will 
			//not be shadowed by the Recipients constructor
		}
	}

	/**
	 * Creates a context for making or verifying Encrypt COSE messages.
	 * 
	 * @param recipients  the list of recipients.
	 * @param alg  the encryption algorithm (from AlgorithmID.*.ASCBOR())
	 * @return  the matching context
	 */	
	public static CwtCryptoCtx encrypt(List<Recipient> recipients, CBORObject alg) {
		return new CwtCryptoCtx(recipients, alg);
	}

	/**
	 * Creates a context for encrypting and decrypting Encrypt0 COSE messages.
	 * 
	 * @param rawSymmetrickey  the raw symmetric key
	 * @param alg  the encryption algorithm (from AlgorithmID.*.ASCBOR())
	 * 
	 * @return  the matching context
	 */
	public static CwtCryptoCtx encrypt0(byte[] rawSymmetrickey, CBORObject alg) {
		return new CwtCryptoCtx(rawSymmetrickey, alg);
	}
	
	/**
	 * Creates a context for making or verifying MAC COSE messages.
	 * 
	 * @param recipients  the list of recipients.
	 * @param alg  the mac algorithm (from AlgorithmID.*.ASCBOR())
	 * @return  the matching context
	 */
	public static CwtCryptoCtx mac(List<Recipient> recipients, CBORObject alg) {
		return new CwtCryptoCtx(recipients, alg);
	}
	
	/**
	 * Creates a context for making or verifying MAC0 COSE messages.
	 * 
	 * @param rawSymmetricKey  the raw symmetric key
	 * @param alg  the algorithm
	 * 
	 * @return  the matching context
	 */
	public static CwtCryptoCtx mac0(byte[] rawSymmetricKey, CBORObject alg) {
		return new CwtCryptoCtx(rawSymmetricKey, alg);
	}
	
	/**
	 * Create a context for making Sign COSE messages.
	 * 
	 * @param signers  the signers
	 * @param alg  the signature algorithm (from AlgorithmID.*.ASCBOR())
	 * @return  the matching context
	 */
	public static CwtCryptoCtx signCreate(List<Signer> signers, CBORObject alg) {
		return new CwtCryptoCtx(signers, alg, true);
	}
	
	
	/**
	 * Create a context for verifying Sign COSE Messages.
	 * 
	 * @param publicKey  the public key to verify the signature
	 * @param alg   the signature algorithm (from AlgorithmID.*.ASCBOR())
	 * @return  the matching context
	 */
	public static CwtCryptoCtx signVerify(CBORObject publicKey, CBORObject alg) {
		return new CwtCryptoCtx(publicKey, null, alg);
	}
	
	/**
	 * Creates a context for verifying Sign1 COSE messages.
	 * 
	 * @param publicKey  the public key of the signer
	 * @param alg  the signing algorithm (from  AlgorithmID.*.ASCBOR())
	 * 
	 * @return  the matching context
	 */
	public static CwtCryptoCtx sign1Verify(CBORObject publicKey, CBORObject alg) {
			return new CwtCryptoCtx(publicKey, null, alg);
	}
	
	/**
	 * Creates a context for signing Sign1 COSE messages.
	 * 
	 * @param privateKey  the private key of the signer
	 * @param alg  the signing algorithm (from  AlgorithmID.*.ASCBOR())
	 * 
	 * @return  the matching context
	 */
	public static CwtCryptoCtx sign1Create(CBORObject privateKey, CBORObject alg) {
		return new CwtCryptoCtx(CBORObject.Null, privateKey, alg);
	}
		
	/**
	 * @return  the signers
	 */
	public List<Signer> getSigners() {
		return this.signers;
	}
	
	/**
	 * @return  the private key
	 */
	public CBORObject getPrivateKey() {
		return this.privatekey;
	}
	
	/**
	 * @return  the algorithm
	 */
	public CBORObject getAlg() {
		return this.alg;
	}

	/**
	 * @return  the symmetric key
	 */
	public byte[] getKey() {
		return this.rawSymmetricKey;
	}
	
	/**
	 * @return  the recipients
	 */
	public List<Recipient> getRecipients() {
		return this.recipients;
	}

	/**
	 * @return  the public key
	 */
	public CBORObject getPublicKey() {
		return this.publicKey;
	}
}
