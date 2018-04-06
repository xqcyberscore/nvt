# OpenVAS Vulnerability Test
# $Id: deb_2566_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2566-1 (exim4)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "It was discovered that Exim, a mail transport agent, is not properly
handling the decoding of DNS records for DKIM.  Specifically, crafted
records can yield to a heap-based buffer overflow.  An attacker can
exploit this flaw to execute arbitrary code.

For the stable distribution (squeeze), this problem has been fixed in
version 4.72-6+squeeze3.

For the testing distribution (wheezy), this problem has been fixed in
version 4.80-5.1.

For the unstable distribution (sid), this problem has been fixed in
version 4.80-5.1.


We recommend that you upgrade your exim4 packages.";
tag_summary = "The remote host is missing an update to exim4
announced via advisory DSA 2566-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202566-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.72537");
 script_cve_id("CVE-2012-5671");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-10-29 10:21:14 -0400 (Mon, 29 Oct 2012)");
 script_name("Debian Security Advisory DSA 2566-1 (exim4)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
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
if((res = isdpkgvuln(pkg:"exim4", ver:"4.72-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-base", ver:"4.72-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-config", ver:"4.72-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-daemon-heavy", ver:"4.72-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-daemon-heavy-dbg", ver:"4.72-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-daemon-light", ver:"4.72-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-daemon-light-dbg", ver:"4.72-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-dbg", ver:"4.72-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-dev", ver:"4.72-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"eximon4", ver:"4.72-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4", ver:"4.80-5.1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-base", ver:"4.80-5.1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-config", ver:"4.80-5.1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-daemon-heavy", ver:"4.80-5.1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-daemon-heavy-dbg", ver:"4.80-5.1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-daemon-light", ver:"4.80-5.1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-daemon-light-dbg", ver:"4.80-5.1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-dbg", ver:"4.80-5.1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"exim4-dev", ver:"4.80-5.1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"eximon4", ver:"4.80-5.1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
