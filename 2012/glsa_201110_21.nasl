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
tag_insight = "Multiple vulnerabilities in Asterisk might allow unauthenticated
    remote attackers to execute arbitrary code.";
tag_solution = "All asterisk 1.6.x users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/asterisk-1.6.2.18.2'
    

All asterisk 1.8.x users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/asterisk-1.8.7.1'
    

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201110-21
http://bugs.gentoo.org/show_bug.cgi?id=352059
http://bugs.gentoo.org/show_bug.cgi?id=355967
http://bugs.gentoo.org/show_bug.cgi?id=359767
http://bugs.gentoo.org/show_bug.cgi?id=364887
http://bugs.gentoo.org/show_bug.cgi?id=372793
http://bugs.gentoo.org/show_bug.cgi?id=373409
http://bugs.gentoo.org/show_bug.cgi?id=387453";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201110-21.";

                                                                                
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70784");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_cve_id("CVE-2011-1147", "CVE-2011-1174", "CVE-2011-1175", "CVE-2011-1507", "CVE-2011-1599", "CVE-2011-2529", "CVE-2011-2535", "CVE-2011-2536", "CVE-2011-2665", "CVE-2011-2666", "CVE-2011-4063");
 script_version("$Revision: 8671 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:38:48 +0100 (Mon, 05 Feb 2018) $");
 script_tag(name:"creation_date", value:"2012-02-12 10:04:40 -0500 (Sun, 12 Feb 2012)");
 script_name("Gentoo Security Advisory GLSA 201110-21 (Asterisk)");



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
if((res = ispkgvuln(pkg:"net-misc/asterisk", unaffected: make_list("ge 1.8.7.1", "rge 1.6.2.18.2"), vulnerable: make_list("lt 1.8.7.1"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
