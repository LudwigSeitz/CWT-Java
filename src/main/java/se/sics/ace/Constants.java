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
package se.sics.ace;

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
		"username", "password", "refresh_token", "alg", "cnf", "profile", 
		"active", "client_token", "rs_cnf"};
	
	
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
}
