# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2004_119_01.nasl 9352 2018-04-06 07:13:02Z cfischer $
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
tag_insight = "New kernel packages are available for Slackware 9.1 and -current to
fix security issues.  Also available are new kernel modules packages
(including alsa-driver), and a new version of the hotplug package
for Slackware 9.1 containing some fixes for using 2.4.26 (and 2.6.x)
kernel modules.

The most serious of the fixed issues is an overflow in ip_setsockopt(),
which could allow a local attacker to gain root access, or to crash or
reboot the machine.  This bug affects 2.4 kernels from 2.4.22 - 2.4.25.
Any sites running one of those kernel versions should upgrade right
away.  After installing the new kernel, be sure to run 'lilo'.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2004-119-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2004-119-01";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.53937");
 script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_cve_id("CVE-2004-0394", "CVE-2004-0424");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 9352 $");
 name = "Slackware Advisory SSA:2004-119-01 kernel security updates ";
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
if(isslkpkgvuln(pkg:"alsa-driver", ver:"0.9.8-i486-3", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"hotplug", ver:"2004_01_05-noarch-1", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-ide", ver:"2.4.26-i486-2", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-headers", ver:"2.4.26-i386-1", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-modules", ver:"2.4.26-i486-1", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-source", ver:"2.4.26-noarch-1", rls:"SLK9.1")) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
