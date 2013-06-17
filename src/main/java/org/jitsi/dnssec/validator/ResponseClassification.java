package org.jitsi.dnssec.validator;

/**
 * These are response subtypes. They are necessary for determining the
 * validation strategy. They have no bearing on the iterative resolution
 * algorithm, so they are confined here.
 */
public enum ResponseClassification {
    /** Not a recognized subtype. */
    UNKNOWN,

    /** A postive, direct, response. */
    POSITIVE,

    /** A postive response, with a CNAME/DNAME chain. */
    CNAME,

    /** A NOERROR/NODATA response. */
    NODATA,

    /** A NXDOMAIN response. */
    NAMEERROR,

    /** A response to a qtype=ANY query. */
    ANY,

    /** A response with CNAMES that points to a non-existing type. */
    CNAME_NODATA,

    /** A response with CNAMES that points into the void. */
    CNAME_NAMEERROR;
}
