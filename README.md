dnssecjava
==========
A DNSSEC validating stub resolver for Java.

[![Build Status](https://travis-ci.org/ibauersachs/dnssecjava.svg?branch=master)](https://travis-ci.org/ibauersachs/dnssecjava)
[![Coverage Status](https://coveralls.io/repos/ibauersachs/dnssecjava/badge.svg)](https://coveralls.io/r/ibauersachs/dnssecjava)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.jitsi/dnssecjava/badge.svg)](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22org.jitsi%22%20AND%20a%3A%22dnssecjava%22)
[![Javadocs](http://javadoc.io/badge/org.jitsi/dnssecjava.svg)](https://javadoc.io/doc/org.jitsi/dnssecjava)

Is this library safe to use?
---------------------------
Maybe. There's been no audit of the code so far, so there are absolutely no
guarantees. The rest depends currently on your use case: the proof that a
positive response is correct _should_ be safe to use. Most of the
NXDOMAIN/NODATA responses are safe too, but there are some corner cases that
have no tests yet.

Unit tests are currently covering over 95% of the code, including 123
from Unbound. Also keep in mind that while most of the code paths are covered
by unit tests, this does not mean it is performing according to the RFCs or
that something that should be checked for is really done.

See the [To-Do list](TODO.md) for more details.

History
-------
This project is based on the work of the Unbound Java prototype from 2005/2006.
The Unbound prototype was stripped from all unnecessary parts, heavily
modified, complemented with more than 300 unit test and found bugs were fixed.

### Released versions
* 1.2.0:
  - Fix CVE-2017-15105
  - Add config option `org.jitsi.dnssec.harden_algo_downgrade`
  - Fix handling of ENT in NSEC3 zones
  - Fix returning YXDOMAIN RCode
  - Requires dnsjava 2.1.9 for proper (EC)DSA signature validation
* 1.1.3:
  - Replace jmockit with PowerMockito due to ever changing API (and there's a Debian package for PowerMockito)
  - Use fixed versions for the dependencies
  - Fix a Javadoc error in ValUtils
* 1.1.2:
  - Issue #7: Provide alternatve to the resource bundle mechanism (thanks to Matt David)
  - Issue #8: Fix parameter in dnskey.anchor_verify_failed (thanks to Andreas Schildbach)
* 1.1.1: Issue #5: Avoid using a regex to split long validation reasons, they don't work on Android
* 1.1:   Change logging to slf4j
* 1.0:   Initial release

Usage
-----
The project is intended to be used as a `Resolver` for
[DNSJAVA](http://www.xbill.org/dnsjava/). Validated, secure responses contain
the DNS `AD`-flag, while responses that failed validation return the
`SERVFAIL`-RCode. Insecure responses return the actual return code
without the `AD`-flag set.
The reason why the validation failed or is insecure is provided as
a localized string in the additional section under the record ./65280/TXT
(a TXT record for the owner name of the root zone in the private query class
`ValidatingResolver.VALIDATION_REASON_QCLASS`).

### Example
```java
import java.io.*;

import org.jitsi.dnssec.validator.ValidatingResolver;
import org.xbill.DNS.*;

public class ResolveExample {
    static String ROOT = ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";

    public static void main(String[] args) throws Exception {
        // Send two sample queries using a standard DNSJAVA resolver
        SimpleResolver sr = new SimpleResolver("4.2.2.1");
        System.out.println("Standard resolver:");
        sendAndPrint(sr, "www.dnssec-failed.org.");
        sendAndPrint(sr, "www.isc.org.");

        // Send the same queries using the validating resolver with the
        // trust anchor of the root zone
        // http://data.iana.org/root-anchors/root-anchors.xml
        ValidatingResolver vr = new ValidatingResolver(sr);
        vr.loadTrustAnchors(new ByteArrayInputStream(ROOT.getBytes("ASCII")));
        System.out.println("\n\nValidating resolver:");
        sendAndPrint(vr, "www.dnssec-failed.org.");
        sendAndPrint(vr, "www.isc.org.");
    }

    private static void sendAndPrint(Resolver vr, String name) throws IOException {
        System.out.println("\n---" + name);
        Record qr = Record.newRecord(Name.fromConstantString(name), Type.A, DClass.IN);
        Message response = vr.send(Message.newQuery(qr));
        System.out.println("AD-Flag: " + response.getHeader().getFlag(Flags.AD));
        System.out.println("RCode:   " + Rcode.string(response.getRcode()));
        for (RRset set : response.getSectionRRsets(Section.ADDITIONAL)) {
            if (set.getName().equals(Name.root) && set.getType() == Type.TXT
                    && set.getDClass() == ValidatingResolver.VALIDATION_REASON_QCLASS) {
                System.out.println("Reason:  " + ((TXTRecord) set.first()).getStrings().get(0));
            }
        }
    }
}

```

This should result in an output like
```
Standard resolver:
---www.dnssec-failed.org.
AD-Flag: false
RCode:   NOERROR
---www.isc.org.
AD-Flag: false
RCode:   NOERROR

Validating resolver:
---www.dnssec-failed.org.
AD-Flag: false
RCode:   SERVFAIL
Reason:  Could not establish a chain of trust to keys for [dnssec-failed.org.]. Reason: Did not match a DS to a DNSKEY.
---www.isc.org.
AD-Flag: true
RCode:   NOERROR
```

Build
-----
Run `mvn package`

Configuration Options
---------------------
The validator supports a few configuration options. These can be set by calling
`ValidatingResolver.init(properties);`

### org.jitsi.dnssec.keycache.max_ttl
Maximum time-to-live (TTL) of entries in the key cache in seconds. The default
is 900s (15min).

### org.jitsi.dnssec.keycache.max_size
Maximum number of entries in the key cache. The default is 1000.

### org.jitsi.dnssec.nsec3.iterations.N
Maximum iteration count for the NSEC3 hashing function depending on the key 
size N. The defaults from [RFC5155](https://tools.ietf.org/html/rfc5155#section-10.3) are:

- 1024 bit keys: 150 iterations (i.e. org.jitsi.dnssec.nsec3.iterations.1024=150)
- 2048 bit keys: 500 iterations 
- 4096 bit keys: 2500 iterations 

### org.jitsi.dnssec.trust\_anchor_file
The file from which the trust anchor should be loaded. There is no default.

It must be formatted like a DNS zone master file. It can only contain DS
or DNSKEY records.

### org.jitsi.dnssec.digest\_preference
Defines the preferred DS record digest algorithm if a zone has registered
multiple DS records. The list is comma-separated, highest preference first.

If this property is not specified, the DS record with the highest [digest ID]
(http://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml) is chosen.
To stay compliant with the RFCs, the mandatory digest IDs must be listed in
this property.

The GOST digest requires [BouncyCastle](https://www.bouncycastle.org/java.html)
on the classpath.

### org.jitsi.dnssec.harden\_algo\_downgrade
Prevent algorithm downgrade when multiple algorithms are advertised in a zones
DS records. If `false`, allows any algorithm to validate the zone.
Default is `true`.

### org.jitsi.dnssec.digest\_enabled.ID
Boolean property to enable or disable a DS record digest algorithm.
See [RFC8624](https://tools.ietf.org/html/rfc8624#section-3.3) for recommended values.

### org.jitsi.dnssec.algorithm\_enabled.ID
Boolean property to enable or disable a DS/DNSKEY algorithm.
See [RFC8624](https://tools.ietf.org/html/rfc8624#section-3.1) for recommended values.
