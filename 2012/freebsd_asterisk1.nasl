#
#VID 4c1ac2dd-c788-11e1-be25-14dae9ebcf89
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 4c1ac2dd-c788-11e1-be25-14dae9ebcf89
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
tag_insight = "The following packages are affected:
   asterisk
   asterisk18

CVE-2012-3812
Double free vulnerability in apps/app_voicemail.c in Asterisk Open
Source 1.8.x before 1.8.13.1 and 10.x before 10.5.2, Certified
Asterisk 1.8.11-certx before 1.8.11-cert4, and Asterisk Digiumphones
10.x.x-digiumphones before 10.5.2-digiumphones allows remote
authenticated users to cause a denial of service (daemon crash) by
establishing multiple voicemail sessions and accessing both the Urgent
mailbox and the INBOX mailbox.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://downloads.digium.com/pub/security/AST-2012-011.html
http://downloads.digium.com/pub/security/AST-2012-012.html
https://www.asterisk.org/security
http://www.vuxml.org/freebsd/4c1ac2dd-c788-11e1-be25-14dae9ebcf89.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71526");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_cve_id("CVE-2012-3812");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
 script_name("FreeBSD Ports: asterisk");


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
bver = portver(pkg:"asterisk");
if(!isnull(bver) && revcomp(a:bver, b:"10")>0 && revcomp(a:bver, b:"10.5.2")<0) {
    txt += "Package asterisk version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"asterisk18");
if(!isnull(bver) && revcomp(a:bver, b:"1.8")>0 && revcomp(a:bver, b:"1.8.13.1")<0) {
    txt += "Package asterisk18 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
