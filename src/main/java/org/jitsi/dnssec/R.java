/*
 * dnssecjava - a DNSSEC validating stub resolver for Java
 * Copyright (C) 2013 Ingo Bauersachs. All rights reserved.
 *
 * This file is part of dnssecjava.
 *
 * Dnssecjava is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Dnssecjava is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with dnssecjava.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.jitsi.dnssec;

import java.text.MessageFormat;
import java.util.ResourceBundle;

/**
 * Utility class to retrieve messages from {@link ResourceBundle}s.
 */
public final class R {
    private static ResourceBundle rb = ResourceBundle.getBundle("messages");

    private R() {
    }

    /**
     * Gets a translated message.
     * @param key The message key to retrieve.
     * @param values The values that fill placeholders in the message.
     * @return The formatted message.
     */
    public static String get(String key, Object... values) {
        return MessageFormat.format(rb.getString(key), values);
    }
}
