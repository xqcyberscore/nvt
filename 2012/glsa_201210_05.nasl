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
tag_insight = "Two vulnerabilities have been found in Bash, the worst of which may
    allow execution of arbitrary code.";
tag_solution = "All Bash users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-shells/bash-4.2_p37'
    

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201210-05
http://bugs.gentoo.org/show_bug.cgi?id=251319
http://bugs.gentoo.org/show_bug.cgi?id=431850";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201210-05.";

                                                                                
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.72521");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2008-5374", "CVE-2012-3410");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-10-22 08:43:44 -0400 (Mon, 22 Oct 2012)");
 script_name("Gentoo Security Advisory GLSA 201210-05 (bash)");



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
if((res = ispkgvuln(pkg:"app-shells/bash", unaffected: make_list("ge 4.2_p37"), vulnerable: make_list("lt 4.2_p37"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
