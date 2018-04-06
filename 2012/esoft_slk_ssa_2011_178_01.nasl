# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2011_178_01.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory SSA:2011-178-01
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
tag_insight = "New pidgin packages are available for Slackware 12.2, 13.0, 13.1, 13.37,
and -current to fix a security issue.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2011-178-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2011-178-01";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71954");
 script_cve_id("CVE-2011-2485");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-09-10 07:16:17 -0400 (Mon, 10 Sep 2012)");
 script_name("Slackware Advisory SSA:2011-178-01 pidgin ");


 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Slackware Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-slack.inc");
vuln = 0;
if(isslkpkgvuln(pkg:"pidgin", ver:"2.9.0-i486-1_slack12.2", rls:"SLK12.2")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"pidgin", ver:"2.9.0-i486-1_slack13.0", rls:"SLK13.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"pidgin", ver:"2.9.0-i486-1_slack13.1", rls:"SLK13.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"pidgin", ver:"2.9.0-i486-1_slack13.37", rls:"SLK13.37")) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
