# OpenVAS Vulnerability Test
# $Id: deb_2506_1.nasl 5963 2017-04-18 09:02:14Z teissa $
# Description: Auto-generated from advisory DSA 2506-1 (libapache-mod-security)
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
tag_insight = "Qualys Vulnerability & Malware Research Labs discovered a vulnerability in
ModSecurity, a security module for the Apache webserver. In situations where
both 'Content:Disposition: attachment' and 'Content-Type: multipart' were
present in HTTP headers, the vulernability could allow an attacker to bypass
policy and execute cross-site script (XSS) attacks through properly crafted
HTML documents.

For the stable distribution (squeeze), this problem has been fixed in
version 2.5.12-1+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 2.6.6-1.

For the unstable distribution (sid), this problem has been fixed in
version 2.6.6-1.

In testing and unstable distribution, the source package has been renamed to
modsecurity-apache.

We recommend that you upgrade your libapache-mod-security packages.";
tag_summary = "The remote host is missing an update to libapache-mod-security
announced via advisory DSA 2506-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202506-1";

if(description)
{
 script_id(71485);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2012-2751");
 script_version("$Revision: 5963 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-18 11:02:14 +0200 (Tue, 18 Apr 2017) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:07:44 -0400 (Fri, 10 Aug 2012)");
 script_name("Debian Security Advisory DSA 2506-1 (libapache-mod-security)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
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
if((res = isdpkgvuln(pkg:"libapache-mod-security", ver:"2.5.12-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"mod-security-common", ver:"2.5.12-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
