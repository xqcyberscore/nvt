#
#VID 0c7a3ee2-3654-11e1-b404-20cf30e32f6d
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 0c7a3ee2-3654-11e1-b404-20cf30e32f6d
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "The following package is affected: bugzilla

CVE-2011-3657
Multiple cross-site scripting (XSS) vulnerabilities in Bugzilla 2.x
and 3.x before 3.4.13; 3.5.x and 3.6.x before 3.6.7; 3.7.x and 4.0.x
before 4.0.3; and 4.1.x through 4.1.3, when debug mode is used, allow
remote attackers to inject arbitrary web script or HTML via vectors
involving a (1) tabular report, (2) graphical report, or (3) new
chart.

CVE-2011-3667
The User.offer_account_by_email WebService method in Bugzilla 2.x and
3.x before 3.4.13; 3.5.x and 3.6.x before 3.6.7; 3.7.x and 4.0.x
before 4.0.3; and 4.1.x through 4.1.3, when createemailregexp is not
empty, does not properly handle user_can_create_account settings,
which allows remote attackers to create user accounts by leveraging a
token contained in an e-mail message.

CVE-2011-3668
Cross-site request forgery (CSRF) vulnerability in post_bug.cgi in
Bugzilla 2.x, 3.x, and 4.x before 4.2rc1 allows remote attackers to
hijack the authentication of arbitrary users for requests that create
bug reports.

CVE-2011-3669
Cross-site request forgery (CSRF) vulnerability in attachment.cgi in
Bugzilla 2.x, 3.x, and 4.x before 4.2rc1 allows remote attackers to
hijack the authentication of arbitrary users for requests that upload
attachments.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://bugzilla.mozilla.org/show_bug.cgi?id=697699
https://bugzilla.mozilla.org/show_bug.cgi?id=711714
https://bugzilla.mozilla.org/show_bug.cgi?id=703975
https://bugzilla.mozilla.org/show_bug.cgi?id=703983
http://www.vuxml.org/freebsd/0c7a3ee2-3654-11e1-b404-20cf30e32f6d.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70581");
 script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-3657", "CVE-2011-3667", "CVE-2011-3668", "CVE-2011-3669");
 script_version("$Revision: 9352 $");
 script_name("FreeBSD Ports: bugzilla");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"bugzilla");
if(!isnull(bver) && revcomp(a:bver, b:"2.4")>=0 && revcomp(a:bver, b:"3.6.7")<0) {
    txt += 'Package bugzilla version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"4.0")>=0 && revcomp(a:bver, b:"4.0.3")<0) {
    txt += 'Package bugzilla version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
