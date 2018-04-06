#
#VID 908f4cf2-1e8b-11e0-a587-001b77d09812
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 908f4cf2-1e8b-11e0-a587-001b77d09812
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
tag_insight = "The following package is affected: sudo

CVE-2011-0010
check.c in sudo 1.7.x before 1.7.4p5, when a Runas group is
configured, does not require a password for command execution that
involves a gid change but no uid change, which allows local users to
bypass an intended authentication requirement via the -g option to a
sudo command.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.sudo.ws/sudo/alerts/runas_group_pw.html
http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=609641
http://www.vuxml.org/freebsd/908f4cf2-1e8b-11e0-a587-001b77d09812.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.68818");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
 script_tag(name:"cvss_base", value:"4.4");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-0010");
 script_name("FreeBSD Ports: sudo");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
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

txt = "";
vuln = 0;
bver = portver(pkg:"sudo");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.0")>=0 && revcomp(a:bver, b:"1.7.4.5")<0) {
    txt += 'Package sudo version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
