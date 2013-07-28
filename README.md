#<center>Work in Progress! Do NOT yet rely on the results!</center>
<hr/>

dnssecjava
==========
A DNSSEC validating stub resolver for Java.

History
-------
This project is based on the work of the Unbound Java prototype
from 2005/2006. The Unbound prototype was stripped from all
unnecessary parts, heavily modified and bugfixed.

Current State
-------------
Unit tests are currently covering over 90% of the code, including 123
from the current production Unbound. Most cases should be sucessfully
validated, there are still untested parts.
See the corresponding TODO-file for details.

Usage
-----
The project is intended to be used as a `Resolver` for
[DNSJAVA](www.xbill.org/dnsjava/). Validated, secure responses contain
the DNS `AD`-flag, while responses that failed validation return the
`SERVFAIL`-RCode. Insecure responses return the actual return code
without the `AD`-flag set.
The reason why the validation failed or is insecure is provided as
a localized string in ./65280/TXT (a TXT record for the owner name
of root zone in the private query class
`ValidatingResolver.VALIDATION_REASON_QCLASS`).

Build
-----
Ideally just run `mvn package`, but see the TODO why this currently
doesn't work. Building is still possible by importing the project into
Eclipse, adding a library reference to the patched DNSJAVA.
