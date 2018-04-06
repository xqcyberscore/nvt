#
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
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
tag_insight = "Multiple vulnerabilities in xine-lib might result in the remote execution
    of arbitrary code.";
tag_solution = "All xine-lib users should upgrade to an unaffected version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/xine-lib-1.1.16.3'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201006-04
http://bugs.gentoo.org/show_bug.cgi?id=234777
http://bugs.gentoo.org/show_bug.cgi?id=249041
http://bugs.gentoo.org/show_bug.cgi?id=260069
http://bugs.gentoo.org/show_bug.cgi?id=265250";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201006-04.";

                                                                                
                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69007");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2008-3231", "CVE-2008-5233", "CVE-2008-5234", "CVE-2008-5235", "CVE-2008-5236", "CVE-2008-5237", "CVE-2008-5238", "CVE-2008-5239", "CVE-2008-5240", "CVE-2008-5241", "CVE-2008-5242", "CVE-2008-5243", "CVE-2008-5244", "CVE-2008-5245", "CVE-2008-5246", "CVE-2008-5247", "CVE-2008-5248", "CVE-2009-0698", "CVE-2009-1274");
 script_name("Gentoo Security Advisory GLSA 201006-04 (xine-lib)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
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
if ((res = ispkgvuln(pkg:"media-libs/xine-lib", unaffected: make_list("ge 1.1.16.3"), vulnerable: make_list("lt 1.1.16.3"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
