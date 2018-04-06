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
tag_insight = "Multiple vulnerabilities have been found in BIND, the worst of
    which allowing to cause remote Denial of Service.";
tag_solution = "All bind users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-dns/bind-9.7.4_p1'
    

NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since December 22, 2011. It is likely that your system is
      already
      no longer affected by this issue.

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-01
http://bugs.gentoo.org/show_bug.cgi?id=347621
http://bugs.gentoo.org/show_bug.cgi?id=356223
http://bugs.gentoo.org/show_bug.cgi?id=368863
http://bugs.gentoo.org/show_bug.cgi?id=374201
http://bugs.gentoo.org/show_bug.cgi?id=374623
http://bugs.gentoo.org/show_bug.cgi?id=390753";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201206-01.";

                                                                                
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71545");
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_cve_id("CVE-2010-3613", "CVE-2010-3614", "CVE-2010-3615", "CVE-2010-3762", "CVE-2011-0414", "CVE-2011-1910", "CVE-2011-2464", "CVE-2011-2465", "CVE-2011-4313");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:22:52 -0400 (Fri, 10 Aug 2012)");
 script_name("Gentoo Security Advisory GLSA 201206-01 (bind)");



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
if((res = ispkgvuln(pkg:"net-dns/bind", unaffected: make_list("ge 9.7.4_p1"), vulnerable: make_list("lt 9.7.4_p1"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
