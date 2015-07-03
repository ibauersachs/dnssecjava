/*
 * dnssecjava - a DNSSEC validating stub resolver for Java
 * Copyright (c) 2013-2015 Ingo Bauersachs
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */

package org.jitsi.dnssec.validator;

import org.jitsi.dnssec.SecurityStatus;

/**
 * Codes for DNSSEC security statuses along with a reason why the status was
 * determined.
 */
class JustifiedSecStatus {
    SecurityStatus status;
    String reason;

    /**
     * Creates a new instance of this class.
     * 
     * @param status The security status.
     * @param reason The reason why the status was determined.
     */
    JustifiedSecStatus(SecurityStatus status, String reason) {
        this.status = status;
        this.reason = reason;
    }
}
