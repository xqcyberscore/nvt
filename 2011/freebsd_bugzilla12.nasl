#
#VID c8c927e5-2891-11e0-8f26-00151735203a
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID c8c927e5-2891-11e0-8f26-00151735203a
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

CVE-2010-4568
Bugzilla 2.14 through 2.22.7; 3.0.x, 3.1.x, and 3.2.x before 3.2.10;
3.4.x before 3.4.10; 3.6.x before 3.6.4; and 4.0.x before 4.0rc2 does
not properly generate random values for cookies and tokens, which
allows remote attackers to obtain access to arbitrary accounts via
unspecified vectors.

CVE-2010-2761
The multipart_init function in (1) CGI.pm before 3.50 and (2)
Simple.pm in CGI::Simple 1.112 and earlier uses a hardcoded value of
the MIME boundary string in multipart/x-mixed-replace content, which
allows remote attackers to inject arbitrary HTTP headers and conduct
HTTP response splitting attacks via crafted input.

CVE-2010-4411
Unspecified vulnerability in CGI.pm 3.50 and earlier allows remote
attackers to inject arbitrary HTTP headers and conduct HTTP response
splitting attacks via unknown vectors.  NOTE: this issue exists because
of an incomplete fix for CVE-2010-2761.

CVE-2010-4572
CRLF injection vulnerability in chart.cgi in Bugzilla before 3.2.10,
3.4.x before 3.4.10, 3.6.x before 3.6.4, and 4.0.x before 4.0rc2
allows remote attackers to inject arbitrary HTTP headers and conduct
HTTP response splitting attacks via the query string, a different
vulnerability than CVE-2010-2761 and CVE-2010-4411.

CVE-2010-4567
Bugzilla before 3.2.10, 3.4.x before 3.4.10, 3.6.x before 3.6.4, and
4.0.x before 4.0rc2 does not properly handle whitespace preceding a
(1) javascript: or (2) data: URI, which allows remote attackers to
conduct cross-site scripting (XSS) attacks.

CVE-2010-0048
Use-after-free vulnerability in WebKit in Apple Safari before 4.0.5
allows remote attackers to execute arbitrary code or cause a denial of
service (application crash).

CVE-2011-0046
Multiple cross-site request forgery (CSRF) vulnerabilities in Bugzilla
before 3.2.10, 3.4.x before 3.4.10, 3.6.x before 3.6.4, and 4.0.x
before 4.0rc2 allow remote attackers to hijack the authentication of
arbitrary users for requests related to (1) adding a saved search in
buglist.cgi, (2) voting in votes.cgi, (3) sanity checking in
sanitycheck.cgi, (4) creating or editing a chart in chart.cgi, (5)
column changing in colchange.cgi, and (6) adding, deleting, or
approving a quip in quips.cgi.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://bugzilla.mozilla.org/show_bug.cgi?id=621591
https://bugzilla.mozilla.org/show_bug.cgi?id=619594
https://bugzilla.mozilla.org/show_bug.cgi?id=591165
https://bugzilla.mozilla.org/show_bug.cgi?id=621572
https://bugzilla.mozilla.org/show_bug.cgi?id=619588
https://bugzilla.mozilla.org/show_bug.cgi?id=628034
https://bugzilla.mozilla.org/show_bug.cgi?id=621090
https://bugzilla.mozilla.org/show_bug.cgi?id=621105
https://bugzilla.mozilla.org/show_bug.cgi?id=621107
https://bugzilla.mozilla.org/show_bug.cgi?id=621108
https://bugzilla.mozilla.org/show_bug.cgi?id=621109
https://bugzilla.mozilla.org/show_bug.cgi?id=621110
http://www.vuxml.org/freebsd/c8c927e5-2891-11e0-8f26-00151735203a.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.68959");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-05 22:25:39 +0100 (Sat, 05 Mar 2011)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-4568", "CVE-2010-2761", "CVE-2010-4411", "CVE-2010-4572", "CVE-2010-4567", "CVE-2010-0048", "CVE-2011-0046");
 script_bugtraq_id(25425);
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
if(!isnull(bver) && revcomp(a:bver, b:"2.14")>=0 && revcomp(a:bver, b:"3.6.4")<0) {
    txt += 'Package bugzilla version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
