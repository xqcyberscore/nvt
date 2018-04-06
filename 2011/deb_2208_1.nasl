# OpenVAS Vulnerability Test
# $Id: deb_2208_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2208-1 (bind9)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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

include("revisions-lib.inc");
tag_insight = "It was discovered that BIND, a DNS server, contains a race condition
when processing zones updates in an authoritative server, either
through dynamic DNS updates or incremental zone transfer (IXFR).  Such
an update while processing a query could result in deadlock and denial
of service.  (CVE-2011-0414)

In addition, this security update addresses a defect related to the
processing of new DNSSEC DS records by the caching resolver, which may
lead to name resolution failures in the delegated zone.  If DNSSEC
validation is enabled, this issue can make domains ending in .COM
unavailable when the DS record for .COM is added to the DNS root zone
on March 31st, 2011.  An unpatched server which is affected by this
issue can be restarted, thus re-enabling resolution of .COM domains.
This workaround applies to the version in oldstable, too.

Configurations not using DNSSEC validations are not affected by this
second issue.

For the oldstable distribution (lenny), the DS record issue will be
fixed soon.  (CVE-2011-0414 does not affect the lenny version.)

For the stable distribution (squeeze), this problem has been fixed in
version 1:9.7.3.dfsg-1~squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 1:9.7.3.dfsg-1.

We recommend that you upgrade your bind9 packages.";
tag_summary = "The remote host is missing an update to bind9
announced via advisory DSA 2208-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202208-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69418");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_cve_id("CVE-2011-0414");
 script_name("Debian Security Advisory DSA 2208-1 (bind9)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"bind9", ver:"1:9.7.3.dfsg-1~squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.7.3.dfsg-1~squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.7.3.dfsg-1~squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.7.3.dfsg-1~squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.7.3.dfsg-1~squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"host", ver:"1:9.7.3.dfsg-1~squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.7.3.dfsg-1~squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind9-60", ver:"1:9.7.3.dfsg-1~squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdns69", ver:"1:9.7.3.dfsg-1~squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisc62", ver:"1:9.7.3.dfsg-1~squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccc60", ver:"1:9.7.3.dfsg-1~squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccfg62", ver:"1:9.7.3.dfsg-1~squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"liblwres60", ver:"1:9.7.3.dfsg-1~squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lwresd", ver:"1:9.7.3.dfsg-1~squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9", ver:"1:9.7.3.dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.7.3.dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.7.3.dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.7.3.dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.7.3.dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"host", ver:"1:9.7.3.dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.7.3.dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind9-60", ver:"1:9.7.3.dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdns69", ver:"1:9.7.3.dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisc62", ver:"1:9.7.3.dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccc60", ver:"1:9.7.3.dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccfg62", ver:"1:9.7.3.dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"liblwres60", ver:"1:9.7.3.dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lwresd", ver:"1:9.7.3.dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
