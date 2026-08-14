/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.util;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Wraps OpenMRS's historical password hashing behind Spring Security's {@link PasswordEncoder}:
 * SHA-512 over {@code password + salt}, with the older SHA-1 variants still accepted so existing
 * rows keep authenticating.
 * <p>
 * OpenMRS keeps the hash and the salt in two separate columns, while {@code PasswordEncoder} works
 * with a single encoded value, so {@link #encode(CharSequence)} returns the two joined as
 * {@code hash:salt} and {@link #matches(CharSequence, String)} accepts that same shape, as well as
 * a bare hash with no salt part. The joined form is a convention internal to this class; it is
 * never itself stored.
 *
 * @since 2.9.0, 3.0.0
 */
public class LegacyOpenmrsPasswordEncoder implements PasswordEncoder {

	@Override
	public String encode(CharSequence rawPassword) {
		return hashAndFormat(rawPassword, Security.getRandomToken());
	}

	/**
	 * Encodes a password using a specific salt instead of generating a new one.
	 * Used for password changes where the existing salt must be preserved
	 * (e.g., to keep secret-answer hashes valid).
	 *
	 * @param rawPassword the password to encode
	 * @param salt the salt to use (must not be null or empty)
	 * @return the encoded password as {@code hash:salt}
	 */
	String encodeWithSalt(CharSequence rawPassword, String salt) {
		if (salt == null || salt.isEmpty()) {
			throw new IllegalArgumentException("Salt must not be null or empty");
		}
		return hashAndFormat(rawPassword, salt);
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		if (encodedPassword == null || rawPassword == null) {
			return false;
		}
		String[] parts = splitHashAndSalt(encodedPassword);
		return Security.hashMatchesLegacy(parts[0], rawPassword.toString() + parts[1]);
	}

	/**
	 * Splits a stored {@code hash:salt} value into its two parts. A hash with no salt part yields
	 * an empty salt.
	 *
	 * @param encodedPassword the stored value
	 * @return String[] where [0] is the hash and [1] is the salt (empty when absent)
	 */
	private String[] splitHashAndSalt(String encodedPassword) {
		String[] parts = encodedPassword.split(":", 2);
		return new String[] { parts[0], parts.length > 1 ? parts[1] : "" };
	}

	/**
	 * Computes the SHA-512 sum of {@code rawPassword + salt} and returns it joined with the salt as
	 * {@code hash:salt}.
	 *
	 * @param rawPassword the raw password
	 * @param salt the salt to use for this encoding
	 * @return the joined value, {@code hash:salt}
	 */
	private String hashAndFormat(CharSequence rawPassword, String salt) {
		String encoded = Security.encodeString(rawPassword.toString() + salt);
		return encoded + ":" + salt;
	}
}
