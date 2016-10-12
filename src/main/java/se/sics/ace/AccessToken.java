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

import com.upokecenter.cbor.CBORObject;

/**
 * An interface with methods that access tokens need to implement.
 *  
 * @author Ludwig Seitz
 *
 */
public interface AccessToken {

	/**
	 * Checks if the token is expired at the given time
	 * 
	 * @param now  the time for which the expiry should be checked
	 * 
	 * @return  true if the token is expired, false if it is still valid
	 * @throws TokenException 
	 */
	public boolean expired(long now) throws TokenException;
	
	/**
	 * Checks if the token is still valid (including expiration).
	 * Note that this method may need to perform introspection.
	 * 
	 * @param now  the time for which validity should be checked
	 * 
	 * @return  true if the token is valid, false if it is invalid
	 * @throws TokenException 
	 */
	public boolean isValid(long now) throws TokenException;
	
	
	/**
	 * Encodes this Access Token as a CBOR Object.
	 * 
	 * @return  the encoding of the token.
	 */
	public CBORObject encode();
	
}
