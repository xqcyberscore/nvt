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
tag_insight = "Multiple vulnerabilities have been found in Puppet, the worst of
    which might allow local attackers to gain escalated privileges.";
tag_solution = "All Puppet users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-admin/puppet-2.7.11'
    

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201203-03
http://bugs.gentoo.org/show_bug.cgi?id=303729
http://bugs.gentoo.org/show_bug.cgi?id=308031
http://bugs.gentoo.org/show_bug.cgi?id=384859
http://bugs.gentoo.org/show_bug.cgi?id=385149
http://bugs.gentoo.org/show_bug.cgi?id=388161
http://bugs.gentoo.org/show_bug.cgi?id=403963";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201203-03.";

                                                                                
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71187");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2009-3564", "CVE-2010-0156", "CVE-2011-3848", "CVE-2011-3869", "CVE-2011-3870", "CVE-2011-3871", "CVE-2011-3872", "CVE-2012-1053", "CVE-2012-1054");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-03-12 11:35:35 -0400 (Mon, 12 Mar 2012)");
 script_name("Gentoo Security Advisory GLSA 201203-03 (puppet)");



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
if((res = ispkgvuln(pkg:"app-admin/puppet", unaffected: make_list("ge 2.7.11"), vulnerable: make_list("lt 2.7.11"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
