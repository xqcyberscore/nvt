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
tag_insight = "Multiple vulnerabilities have been found in CUPS, some of which may
allow execution of arbitrary code or local privilege escalation.";
tag_solution = "All CUPS users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-print/cups-1.4.8-r1'
    

NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since September 03, 2011. It is likely that your system is
      already no longer affected by this issue.

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201207-10
http://bugs.gentoo.org/show_bug.cgi?id=295256
http://bugs.gentoo.org/show_bug.cgi?id=308045
http://bugs.gentoo.org/show_bug.cgi?id=325551
http://bugs.gentoo.org/show_bug.cgi?id=380771";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201207-10.";

                                                                                
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71590");
 script_tag(name:"cvss_base", value:"7.9");
 script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2009-3553", "CVE-2010-0302", "CVE-2010-0393", "CVE-2010-0540", "CVE-2010-0542", "CVE-2010-1748", "CVE-2010-2431", "CVE-2010-2432", "CVE-2010-2941", "CVE-2011-3170");
 script_version("$Revision: 8671 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:38:48 +0100 (Mon, 05 Feb 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:22:56 -0400 (Fri, 10 Aug 2012)");
 script_name("Gentoo Security Advisory GLSA 201207-10 (cups)");



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
if((res = ispkgvuln(pkg:"net-print/cups", unaffected: make_list("ge 1.4.8-r1"), vulnerable: make_list("lt 1.4.8-r1"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
