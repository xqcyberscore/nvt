# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2005_286_01.nasl 8671 2018-02-05 16:38:48Z teissa $
# Description: Auto-generated from the corresponding slackware advisory
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
tag_insight = "New OpenSSL packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1,
10.2, and -current to fix a security issue.  Under certain conditions, an
attacker acting as a 'man in the middle' may force a client and server to
fall back to the less-secure SSL 2.0 protocol.

More details about this issue may be found here:

http://www.openssl.org/news/secadv_20051011.txt";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2005-286-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2005-286-01";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.55636");
 script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:38:48 +0100 (Mon, 05 Feb 2018) $");
 script_bugtraq_id(15647, 15071);
 script_cve_id("CVE-2005-2969");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_version("$Revision: 8671 $");
 name = "Slackware Advisory SSA:2005-286-01 OpenSSL ";
 script_name(name);



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Slackware Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack");
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

include("pkg-lib-slack.inc");
vuln = 0;
if(isslkpkgvuln(pkg:"openssl", ver:"0.9.6m-i386-2", rls:"SLK8.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.6m-i386-2", rls:"SLK8.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl", ver:"0.9.7d-i386-2", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.7d-i386-2", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl", ver:"0.9.7d-i486-2", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.7d-i486-2", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl", ver:"0.9.7d-i486-2", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.7d-i486-2", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl", ver:"0.9.7e-i486-4", rls:"SLK10.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.7e-i486-4", rls:"SLK10.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl", ver:"0.9.7g-i486-2", rls:"SLK10.2")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.7g-i486-2", rls:"SLK10.2")) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
