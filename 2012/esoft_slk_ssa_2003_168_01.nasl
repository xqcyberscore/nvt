# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2003_168_01.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from the corresponding slackware advisory
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
tag_insight = "Precompiled Linux 2.4.21 kernels and source packages are now available for
Slackware 9.0 and -current.  These provide an improved version of the
ptrace fix that had been applied to 2.4.20 in Slackware 9.0 (for example,
command line options now appear correctly when root does 'ps ax'), and
fix a potential denial of service problem with netfilter.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2003-168-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2003-168-01";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.53892");
 script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_bugtraq_id(7601);
 script_cve_id("CVE-2003-0244");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_version("$Revision: 9352 $");
 name = "Slackware Advisory SSA:2003-168-01 2.4.21 kernels available ";
 script_name(name);



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
if(isslkpkgvuln(pkg:"kernel-headers", ver:"2.4.21-i386-1", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-ide", ver:"2.4.21-i486-1", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-modules", ver:"2.4.21_xfs-i486-1", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-source", ver:"2.4.21-noarch-1", rls:"SLK9.0")) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
