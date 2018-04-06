#
#VID dc8741b9-c5d5-11e0-8a8e-00151735203a
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID dc8741b9-c5d5-11e0-8a8e-00151735203a
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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

CVE-2011-2379
Cross-site scripting (XSS) vulnerability in Bugzilla 2.4 through
2.22.7, 3.0.x through 3.3.x, 3.4.x before 3.4.12, 3.5.x, 3.6.x before
3.6.6, 3.7.x, 4.0.x before 4.0.2, and 4.1.x before 4.1.3, when
Internet Explorer before 9 or Safari before 5.0.6 is used for Raw
Unified mode, allows remote attackers to inject arbitrary web script
or HTML via a crafted patch, related to content sniffing.

CVE-2011-2380
Bugzilla 2.23.3 through 2.22.7, 3.0.x through 3.3.x, 3.4.x before
3.4.12, 3.5.x, 3.6.x before 3.6.6, 3.7.x, 4.0.x before 4.0.2, and
4.1.x before 4.1.3 allows remote attackers to determine the existence
of private group names via a crafted parameter during (1) bug creation
or (2) bug editing.

CVE-2011-2979
Bugzilla 4.1.x before 4.1.3 generates different responses for certain
assignee queries depending on whether the group name is valid, which
allows remote attackers to determine the existence of private group
names via a custom search.  NOTE: this vulnerability exists because of
a CVE-2010-2756 regression.

CVE-2011-2381
CRLF injection vulnerability in Bugzilla 2.17.1 through 2.22.7, 3.0.x
through 3.3.x, 3.4.x before 3.4.12, 3.5.x, 3.6.x before 3.6.6, 3.7.x,
4.0.x before 4.0.2, and 4.1.x before 4.1.3 allows remote attackers to
inject arbitrary e-mail headers via an attachment description in a
flagmail notification.

CVE-2011-2978
Bugzilla 2.16rc1 through 2.22.7, 3.0.x through 3.3.x, 3.4.x before
3.4.12, 3.5.x, 3.6.x before 3.6.6, 3.7.x, 4.0.x before 4.0.2, and
4.1.x before 4.1.3 does not prevent changes to the confirmation e-mail
address (aka old_email field) for e-mail change notifications, which
makes it easier for remote attackers to perform arbitrary address
changes by leveraging an unattended workstation.

CVE-2011-2977
Bugzilla 3.6.x before 3.6.6, 3.7.x, 4.0.x before 4.0.2, and 4.1.x
before 4.1.3 on Windows does not delete the temporary files associated
with uploaded attachments, which allows local users to obtain
sensitive information by reading these files.  NOTE: this issue exists
because of a regression in 3.6.

CVE-2011-2976
Cross-site scripting (XSS) vulnerability in Bugzilla 2.16rc1 through
2.22.7, 3.0.x through 3.3.x, and 3.4.x before 3.4.12 allows remote
attackers to inject arbitrary web script or HTML via vectors involving
a BUGLIST cookie.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://bugzilla.mozilla.org/show_bug.cgi?id=637981
https://bugzilla.mozilla.org/show_bug.cgi?id=653477
https://bugzilla.mozilla.org/show_bug.cgi?id=674497
https://bugzilla.mozilla.org/show_bug.cgi?id=657158
https://bugzilla.mozilla.org/show_bug.cgi?id=670868
https://bugzilla.mozilla.org/show_bug.cgi?id=660502
https://bugzilla.mozilla.org/show_bug.cgi?id=660053
http://www.vuxml.org/freebsd/dc8741b9-c5d5-11e0-8a8e-00151735203a.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70264");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2011-2379", "CVE-2011-2380", "CVE-2011-2979", "CVE-2011-2381", "CVE-2011-2978", "CVE-2011-2977", "CVE-2011-2976");
 script_name("FreeBSD Ports: bugzilla");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
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
if(!isnull(bver) && revcomp(a:bver, b:"2.4")>=0 && revcomp(a:bver, b:"3.6.6")<0) {
    txt += 'Package bugzilla version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"4.0")>=0 && revcomp(a:bver, b:"4.0.2")<0) {
    txt += 'Package bugzilla version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
