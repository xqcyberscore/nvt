#
#VID 2eda0c54-34ab-11e0-8103-00215c6a37bb
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 2eda0c54-34ab-11e0-8103-00215c6a37bb
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
tag_insight = "The following packages are affected:
   opera
   opera-devel
   linux-opera

CVE-2011-0450
The downloads manager in Opera before 11.01 on Windows does not
properly determine the pathname of the filesystem-viewing application,
which allows user-assisted remote attackers to execute arbitrary code
via a crafted web site that hosts an executable file.

CVE-2011-0681
The Cascading Style Sheets (CSS) Extensions for XML implementation in
Opera before 11.01 recognizes links to javascript: URLs in the -o-link
property, which makes it easier for remote attackers to bypass CSS
filtering via a crafted URL.

CVE-2011-0682
Integer truncation error in opera.dll in Opera before 11.01 allows
remote attackers to execute arbitrary code or cause a denial of
service (memory corruption) via an HTML form with a select element
that contains a large number of children.

CVE-2011-0683
Opera before 11.01 does not properly restrict the use of opera: URLs,
which makes it easier for remote attackers to conduct clickjacking
attacks via a crafted web site.

CVE-2011-0684
Opera before 11.01 does not properly handle redirections and
unspecified other HTTP responses, which allows remote web servers to
obtain sufficient access to local files to use these files as page
resources, and consequently obtain potentially sensitive information
from the contents of the files, via an unknown response manipulation.

CVE-2011-0685
The Delete Private Data feature in Opera before 11.01 does not
properly implement the 'Clear all email account passwords' option,
which might allow physically proximate attackers to access an e-mail
account via an unattended workstation.

CVE-2011-0686
Unspecified vulnerability in Opera before 11.01 allows remote
attackers to cause a denial of service (application crash) via unknown
content on a web page, as demonstrated by vkontakte.ru.

CVE-2011-0687
Opera before 11.01 does not properly implement Wireless Application
Protocol (WAP) dropdown lists, which allows user-assisted remote
attackers to cause a denial of service (application crash) via a
crafted WAP document.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.opera.com/support/kb/view/982/
http://www.opera.com/support/kb/view/983/
http://www.opera.com/support/kb/view/984/
http://secunia.com/advisories/43023
http://www.vuxml.org/freebsd/2eda0c54-34ab-11e0-8103-00215c6a37bb.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.68952");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-05 22:25:39 +0100 (Sat, 05 Mar 2011)");
 script_cve_id("CVE-2011-0450", "CVE-2011-0681", "CVE-2011-0682", "CVE-2011-0683", "CVE-2011-0684", "CVE-2011-0685", "CVE-2011-0686", "CVE-2011-0687");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: opera, opera-devel, linux-opera");



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
bver = portver(pkg:"opera");
if(!isnull(bver) && revcomp(a:bver, b:"11.01")<0) {
    txt += 'Package opera version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"opera-devel");
if(!isnull(bver) && revcomp(a:bver, b:"11.01")<0) {
    txt += 'Package opera-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-opera");
if(!isnull(bver) && revcomp(a:bver, b:"11.01")<0) {
    txt += 'Package linux-opera version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
