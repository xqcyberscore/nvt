#
#VID 55587adb-b49d-11e1-8df1-0004aca374af
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 55587adb-b49d-11e1-8df1-0004aca374af
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
tag_insight = "The following package is affected: mantis

CVE-2012-2691
The mc_issue_note_update function in the SOAP API in MantisBT before
1.2.11 does not properly check privileges, which allows remote
attackers with bug reporting privileges to edit arbitrary bugnotes via
a SOAP request.
CVE-2012-2692
MantisBT before 1.2.11 does not check the delete_attachments_threshold
permission when form_security_validation is set to OFF, which allows
remote authenticated users with certain privileges to bypass intended
access restrictions and delete arbitrary attachments.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.openwall.com/lists/oss-security/2012/06/09/1
http://sourceforge.net/mailarchive/forum.php?thread_name=1339229952.28538.22%40d.hx.id.au&forum_name=mantisbt-dev
http://www.vuxml.org/freebsd/55587adb-b49d-11e1-8df1-0004aca374af.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71539");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2012-2691", "CVE-2012-2692");
 script_version("$Revision: 8671 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:38:48 +0100 (Mon, 05 Feb 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
 script_name("FreeBSD Ports: mantis");


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
bver = portver(pkg:"mantis");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.11")<0) {
    txt += "Package mantis version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
