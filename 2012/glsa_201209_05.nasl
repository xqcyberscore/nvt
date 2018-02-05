#
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
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
tag_insight = "Multiple vulnerabilities have been found in LibreOffice, allowing
remote attackers to execute arbitrary code or cause a Denial of
Service.";
tag_solution = "All LibreOffice users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-office/libreoffice-3.5.5.3'
    

All users of the LibreOffice binary package should upgrade to the latest
      version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-office/libreoffice-bin-3.5.5.3'
    

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201209-05
http://bugs.gentoo.org/show_bug.cgi?id=386081
http://bugs.gentoo.org/show_bug.cgi?id=409455
http://bugs.gentoo.org/show_bug.cgi?id=416457
http://bugs.gentoo.org/show_bug.cgi?id=429482";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201209-05.";

                                                                                
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.72422");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-2713", "CVE-2012-0037", "CVE-2012-1149", "CVE-2012-2665");
 script_version("$Revision: 8649 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:43 +0100 (Sat, 03 Feb 2018) $");
 script_tag(name:"creation_date", value:"2012-09-26 11:20:49 -0400 (Wed, 26 Sep 2012)");
 script_name("Gentoo Security Advisory GLSA 201209-05 (libreoffice)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Gentoo Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
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

include("pkg-lib-gentoo.inc");
res = "";
report = "";
if((res = ispkgvuln(pkg:"app-office/libreoffice", unaffected: make_list("ge 3.5.5.3"), vulnerable: make_list("lt 3.5.5.3"))) != NULL ) {
    report += res;
}
if((res = ispkgvuln(pkg:"app-office/libreoffice-bin", unaffected: make_list("ge 3.5.5.3"), vulnerable: make_list("lt 3.5.5.3"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
