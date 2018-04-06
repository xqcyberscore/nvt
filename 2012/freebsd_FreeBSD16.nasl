#
#VID aed44c4e-c067-11e1-b5e0-000c299b62e1
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID aed44c4e-c067-11e1-b5e0-000c299b62e1
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
tag_insight = "The following package is affected: FreeBSD

CVE-2012-0217
The x86-64 kernel system-call functionality in Xen 4.1.2 and earlier,
as used in Citrix XenServer 6.0.2 and earlier and other products;
Oracle Solaris 11 and earlier; illumos before r13724; Joyent SmartOS
before 20120614T184600Z; FreeBSD before 9.0-RELEASE-p3; NetBSD 6.0
Beta and earlier; and Microsoft Windows Server 2008 R2 and R2 SP1 and
Windows 7 Gold and SP1, when running on an Intel processor,
incorrectly uses the sysret path in cases where a certain address is
not a canonical address, which allows local users to gain privileges
via a crafted application.  NOTE: this description clearly does not
belong in CVE, because a single entry cannot be about independent
codebases; however, there was some value in preserving the original
mapping of the multi-codebase coordinated-disclosure effort to a
single identifier.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71530");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-0217");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
 script_name("FreeBSD Ports: FreeBSD");


 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
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

include("pkg-lib-bsd.inc");
vuln = 0;
txt = "";
bver = portver(pkg:"FreeBSD");
if(!isnull(bver) && revcomp(a:bver, b:"7.4")>=0 && revcomp(a:bver, b:"7.4_9")<0) {
    txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.1")>=0 && revcomp(a:bver, b:"8.1_12")<0) {
    txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.2")>=0 && revcomp(a:bver, b:"8.2_9")<0) {
    txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.3")>=0 && revcomp(a:bver, b:"8.3_3")<0) {
    txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"9.0")>=0 && revcomp(a:bver, b:"9.0_3")<0) {
    txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
