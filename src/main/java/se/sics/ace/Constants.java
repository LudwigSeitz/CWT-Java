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
package se.sics.ace;

import java.util.HashMap;
import java.util.Map;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/**
 * Constants for use with the ACE framework.
 * 
 * @author Ludwig Seitz
 *
 */
public class Constants {
	
	/** 
	 * General OAuth related abbreviations
	 */
	public static final int ISS = 1; // Major type 3 (text string)
	public static final int SUB = 2; //3
	public static final int AUD = 3; //3
	public static final int EXP = 4; // MT 6 tag 1 (Epoch-based date/time)
	public static final int NBF = 5; // 6t1
	public static final int IAT = 6; // 6t1
	public static final int CTI = 7; // Major type 2 (byte string)
	public static final int CLIENT_ID = 8; // Major type 3
	public static final int CLIENT_SECRET = 9; // Major type 2
	public static final int RESPONSE_TYPE = 10; // 3
	public static final int REDIRECT_URI = 11; //3
	public static final int SCOPE = 12; //3
	public static final int STATE = 13; //3
	public static final int CODE = 14; //2
	public static final int ERROR_DESCRIPTION = 15; //3
	public static final int ERROR_URI = 16; //3
	public static final int GRANT_TYPE = 17; // Major type 0 (uint)
	public static final int ACCESS_TOKEN = 18; // 
	public static final int TOKEN_TYPE = 19; // 0
	public static final int EXPIRES_IN = 20; // 0
	public static final int USERNAME = 21; //3
	public static final int PASSWORD = 22; //3
	public static final int REFRESH_TOKEN = 23; //3
	public static final int CNF = 24; // Major type 5 (map)
	public static final int PROFILE = 25; //0
	public static final int TOKEN = 26; // 3
	public static final int TOKEN_TYPE_HINT = 27; //3 
	public static final int ACTIVE = 28; // boolean
	public static final int CLIENT_TOKEN = 29; //5
	public static final int RS_CNF = 30; //5
	
	/**
	 * Array of String values for the abbreviations
	 */
	public static final String[] ABBREV = {"", "iss", "sub", "aud", "exp", 
		"nbf", "iat", "cti", "client_id", "client_secret", "response_type",
		"redirect_uri", "scope", "state", "code", "error_description", 
		"error_uri", "grant_type", "access_token", "token_type", "expires_in",
		"username", "password", "refresh_token", "cnf", "profile", "token",
		"token_type_hint", "active", "client_token", "rs_cnf"};
	
	
	/**
	 * CWT claims
	 */
	public static final int[] CWT_CLAIMS 
		= {ISS, SUB, AUD, EXP, NBF, IAT, CTI, SCOPE};
	
	/**
	 * ACE-OAUTH-AUTHZ /token parameters
	 */
	public static final int[] TOKEN_PAR = {CLIENT_ID, CLIENT_SECRET, AUD, 
		RESPONSE_TYPE, REDIRECT_URI, SCOPE, STATE, CODE, ERROR_DESCRIPTION, 
		ERROR_URI, GRANT_TYPE, ACCESS_TOKEN, TOKEN_TYPE, EXPIRES_IN, USERNAME,
		PASSWORD, REFRESH_TOKEN, CNF, PROFILE};

   /**
    * ACE-OAUTH-AUTHZ /introspect parameters
    */
	public static final int[] INTROSPECT_PAR = {ACTIVE, USERNAME, CLIENT_ID, SCOPE, 
		TOKEN_TYPE, EXP, IAT, NBF, SUB, AUD, ISS, CTI, CNF, CLIENT_TOKEN,
		RS_CNF};
	
	
	/**
	 * grant types		
	 */
	public static final int GT_PASSWORD = 0;
	public static final int GT_AUTHZ_CODE = 1;
	public static final int GT_CLI_CRED = 2;
	public static final int GT_REF_TOK = 3;


	/**
	 * RESTful action names
	 */
	public static final String[] RESTactionS = {"GET", "POST", "PUT", "DELETE"};
	
	/**
	 * Provides the integer abbreviation of a claim or parameter name.
	 * @param name
	 * @return  the abbreviation or -1 if there is none
	 */
	public static short getAbbrev(String name) {
		for (short i=1; i<ABBREV.length; i++) {
			if (name.equals(ABBREV[i])) {
				return i;
			}
		}
		return -1;	
	}
		   
    /**
    * Remaps a parameter map to the unabbreviated version.
    * 
    * @param map
    */
   public static void unabbreviate(CBORObject map) {
       if (!map.getType().equals(CBORType.Map)) {
           return;
       }
       Map<CBORObject, CBORObject> replacer = new HashMap<>();
       for (CBORObject key : map.getKeys()) {
           if (key.isIntegral()) {
               int keyInt = key.AsInt32();
               if (keyInt > 0 && keyInt < Constants.ABBREV.length) {
                   replacer.put(key, 
                           CBORObject.FromObject(Constants.ABBREV[keyInt]));
                   
               }
           }
       }
       for (CBORObject key : replacer.keySet()) {
           CBORObject value = map.get(key);
           map.Remove(key);
           map.Add(replacer.get(key), value);
       }
   }
}
