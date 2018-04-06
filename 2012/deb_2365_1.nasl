# OpenVAS Vulnerability Test
# $Id: deb_2365_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2365-1 (dtc)
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
tag_insight = "Ansgar Burchardt, Mike O'Connor and Philipp Kern discovered multiple
vulnerabilities in DTC, a web control panel for admin and accounting
hosting services:

CVE-2011-3195

A possible shell insertion has been found in the mailing list
handling.

CVE-2011-3196

Unix rights for the apache2.conf were set incorrectly (world
readable).

CVE-2011-3197

Incorrect input sanitising for the $_SERVER[addrlink] parameter
could lead to SQL insertion.

CVE-2011-3198

DTC was using the -b option of htpasswd, possibly revealing
password in clear text using ps or reading /proc.

CVE-2011-3199

A possible HTML/javascript insertion vulnerability has been found
in the DNS & MX section of the user panel.

This update also fixes several vulnerabilities, for which no CVE ID
has been assigned:

It has been discovered that DTC performs insufficient input sanitising
in the package installer, leading to possible unwanted destination
directory for installed packages if some DTC application packages
are installed (note that these aren't available in Debian main).

DTC was setting-up /etc/sudoers with permissive sudo rights to
chrootuid.

Incorrect input sanitizing in the package installer could lead to
SQL insertion.

A malicious user could enter a specially crafted support ticket
subject leading to an SQL injection in the draw_user_admin.php.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.29.18-1+lenny2

The stable distribution (squeeze) doesn't include dtc.

For the unstable distribution (sid), this problem has been fixed in
version 0.34.1-1.

We recommend that you upgrade your dtc packages.";
tag_summary = "The remote host is missing an update to dtc
announced via advisory DSA 2365-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202365-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70577");
 script_cve_id("CVE-2011-3195", "CVE-2011-3196", "CVE-2011-3197",
               "CVE-2011-3198", "CVE-2011-3199");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-11 02:34:48 -0500 (Sat, 11 Feb 2012)");
 script_name("Debian Security Advisory DSA 2365-1 (dtc)");


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
if((res = isdpkgvuln(pkg:"dtc-common", ver:"0.29.18-1+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"dtc-core", ver:"0.29.18-1+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"dtc-cyrus", ver:"0.29.18-1+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"dtc-postfix-courier", ver:"0.29.18-1+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"dtc-stats-daemon", ver:"0.29.18-1+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"dtc-toaster", ver:"0.29.18-1+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
