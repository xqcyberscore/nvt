# OpenVAS Vulnerability Test
# $Id: deb_2301_2.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2301-2 (rails)
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
tag_insight = "It was discovered that the last security update for Ruby on Rails,
DSA-2301-1, introduced a regression in the libactionpack-ruby package.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.1.0-7+lenny2.

For the stable distribution (squeeze), this problem has been fixed in
version 2.3.5-1.2+squeeze2.

We recommend that you upgrade your rails packages.";
tag_summary = "The remote host is missing an update to rails
announced via advisory DSA 2301-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202301-2";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70710");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-2930", "CVE-2011-2931", "CVE-2011-3186", "CVE-2009-4214");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-11 03:28:39 -0500 (Sat, 11 Feb 2012)");
 script_name("Debian Security Advisory DSA 2301-2 (rails)");


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
if((res = isdpkgvuln(pkg:"rails", ver:"2.1.0-7+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libactionmailer-ruby", ver:"2.3.5-1.2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libactionmailer-ruby1.8", ver:"2.3.5-1.2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libactionpack-ruby", ver:"2.3.5-1.2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libactionpack-ruby1.8", ver:"2.3.5-1.2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libactiverecord-ruby", ver:"2.3.5-1.2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libactiverecord-ruby1.8", ver:"2.3.5-1.2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libactiverecord-ruby1.9.1", ver:"2.3.5-1.2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libactiveresource-ruby", ver:"2.3.5-1.2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libactiveresource-ruby1.8", ver:"2.3.5-1.2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libactivesupport-ruby", ver:"2.3.5-1.2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libactivesupport-ruby1.8", ver:"2.3.5-1.2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libactivesupport-ruby1.9.1", ver:"2.3.5-1.2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"rails", ver:"2.3.5-1.2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"rails-doc", ver:"2.3.5-1.2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"rails-ruby1.8", ver:"2.3.5-1.2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
