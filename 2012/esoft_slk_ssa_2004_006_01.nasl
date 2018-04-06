# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2004_006_01.nasl 9352 2018-04-06 07:13:02Z cfischer $
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
tag_insight = "New kernels are available for Slackware 9.0, 9.1 and -current.
The 9.1 and -current kernels have been upgraded to 2.4.24, and a
fix has been backported to the 2.4.21 kernels in Slackware 9.0
to fix a bounds-checking problem in the kernel's mremap() call
which could be used by a local attacker to gain root privileges.
Sites should upgrade to the 2.4.24 kernel and kernel modules.
After installing the new kernel, be sure to run 'lilo'.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2004-006-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2004-006-01";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.53950");
 script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_bugtraq_id(9356);
 script_cve_id("CVE-2003-0985");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 9352 $");
 name = "Slackware Advisory SSA:2004-006-01 Kernel security update  ";
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
if(isslkpkgvuln(pkg:"kernel-ide", ver:"2.4.21-i486-3", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-source", ver:"2.4.21-noarch-3", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-ide", ver:"2.4.24-i486-1", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-modules", ver:"2.4.24-i486-1", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-source", ver:"2.4.24-noarch-1", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"alsa-driver", ver:"0.9.8-i486-2", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-modules-xfs", ver:"0.9.8-i486-2", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-modules-xfs", ver:"2.4.24-i486-1", rls:"SLK9.1")) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
