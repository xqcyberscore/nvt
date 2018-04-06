# OpenVAS Vulnerability Test
# $Id: deb_2865.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 2865-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_affected  = "postgresql-9.1 on Debian Linux";
tag_insight   = "PostgreSQL is a fully featured object-relational database management
system. It supports a large part of the SQL standard and is designed
to be extensible by users in many aspects. Some of the features are:
ACID transactions, foreign keys, views, sequences, subqueries,
triggers, user-defined types and functions, outer joins, multiversion
concurrency control. Graphical user interfaces and bindings for many
programming languages are available as well.";
tag_solution  = "For the stable distribution (wheezy), these problems have been fixed in
version 9.1_9.1.12-0wheezy1.

For the unstable distribution (sid), these problems have been fixed in
version 9.3.3-1 of the postgresql-9.3 package.

We recommend that you upgrade your postgresql-9.1 packages.";
tag_summary   = "Various vulnerabilities were discovered in PostgreSQL:

CVE-2014-0060 Shore up GRANT ... WITH ADMIN OPTION restrictions (Noah Misch)

Granting a role without ADMIN OPTION is supposed to prevent the grantee
from adding or removing members from the granted role, but this
restriction was easily bypassed by doing SET ROLE first. The security
impact is mostly that a role member can revoke the access of others,
contrary to the wishes of his grantor. Unapproved role member additions
are a lesser concern, since an uncooperative role member could provide
most of his rights to others anyway by creating views or SECURITY
DEFINER functions.

CVE-2014-0061 Prevent privilege escalation via manual calls to PL validator functions
(Andres Freund)

The primary role of PL validator functions is to be called implicitly
during CREATE FUNCTION, but they are also normal SQL functions that a
user can call explicitly. Calling a validator on a function actually
written in some other language was not checked for and could be
exploited for privilege-escalation purposes. The fix involves adding a
call to a privilege-checking function in each validator function.
Non-core procedural languages will also need to make this change to
their own validator functions, if any.

CVE-2014-0062 Avoid multiple name lookups during table and index DDL
(Robert Haas, Andres Freund)

If the name lookups come to different conclusions due to concurrent
activity, we might perform some parts of the DDL on a different table
than other parts. At least in the case of CREATE INDEX, this can be used
to cause the permissions checks to be performed against a different
table than the index creation, allowing for a privilege escalation
attack.

CVE-2014-0063 Prevent buffer overrun with long datetime strings (Noah Misch)

The MAXDATELEN constant was too small for the longest possible value of
type interval, allowing a buffer overrun in interval_out(). Although the
datetime input functions were more careful about avoiding buffer
overrun, the limit was short enough to cause them to reject some valid
inputs, such as input containing a very long timezone name. The ecpg
library contained these vulnerabilities along with some of its own.

CVE-2014-0064 Prevent buffer overrun due to integer overflow in size calculations
(Noah Misch, Heikki Linnakangas)

Several functions, mostly type input functions, calculated an allocation
size without checking for overflow. If overflow did occur, a too-small
buffer would be allocated and then written past.

CVE-2014-0065 Prevent overruns of fixed-size buffers (Peter Eisentraut, Jozef Mlich)

Use strlcpy() and related functions to provide a clear guarantee that
fixed-size buffers are not overrun. Unlike the preceding items, it is
unclear whether these cases really represent live issues, since in most
cases there appear to be previous constraints on the size of the input
string. Nonetheless it seems prudent to silence all Coverity warnings of
this type.

CVE-2014-0066 Avoid crashing if crypt() returns NULL (Honza Horak, Bruce Momjian)
There are relatively few scenarios in which crypt() could return NULL,
but contrib/chkpass would crash if it did. One practical case in which
this could be an issue is if libc is configured to refuse to execute
unapproved hashing algorithms (e.g., FIPS mode 
).

CVE-2014-0067 Document risks of make check in the regression testing instructions
(Noah Misch, Tom Lane)
Since the temporary server started by make check uses trust 

authentication, another user on the same machine could connect to it as
database superuser, and then potentially exploit the privileges of the
operating-system user who started the tests. A future release will
probably incorporate changes in the testing procedure to prevent this
risk, but some public discussion is needed first. So for the moment,
just warn people against using make check when there are untrusted users
on the same machine.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702865");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066", "CVE-2014-0067");
    script_name("Debian Security Advisory DSA 2865-1 (postgresql-9.1 - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-02-20 00:00:00 +0100 (Thu, 20 Feb 2014)");
    script_tag(name:"cvss_base", value:"6.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-2865.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: tag_affected);
    script_tag(name: "insight",   value: tag_insight);
#    script_tag(name: "impact",    value: tag_impact);
    script_tag(name: "solution",  value: tag_solution);
    script_tag(name: "summary",   value: tag_summary);
    script_tag(name: "vuldetect", value: tag_vuldetect);
    script_tag(name:"qod_type", value:"package");
    script_tag(name:"solution_type", value:"VendorFix");

    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libecpg-compat3", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-dev", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg6", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpgtypes3", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq-dev", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq5", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-9.1-dbg", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plperl-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plpython-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plpython3-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-pltcl-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-server-dev-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-compat3", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-dev", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg6", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpgtypes3", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq-dev", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq5", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-9.1-dbg", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plperl-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plpython-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plpython3-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-pltcl-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-server-dev-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-compat3", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-dev", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg6", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpgtypes3", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq-dev", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq5", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-9.1-dbg", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plperl-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plpython-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plpython3-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-pltcl-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-server-dev-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-compat3", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-dev", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg6", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpgtypes3", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq-dev", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq5", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-9.1-dbg", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plperl-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plpython-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plpython3-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-pltcl-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-server-dev-9.1", ver:"9.1_9.1.12-0wheezy1", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
