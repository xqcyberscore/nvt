#
#VID fa2f386f-4814-11e1-89b4-001ec9578670
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID fa2f386f-4814-11e1-89b4-001ec9578670
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
tag_insight = "The following package is affected: acroread9

CVE-2011-2462
Unspecified vulnerability in the U3D component in Adobe Reader and
Acrobat 10.1.1 and earlier on Windows and Mac OS X, and Adobe Reader
9.x through 9.4.6 on UNIX, allows remote attackers to execute
arbitrary code or cause a denial of service (memory corruption) via
unknown vectors, as exploited in the wild in December 2011.

CVE-2011-1353
Unspecified vulnerability in Adobe Reader 10.x before 10.1.1 on
Windows allows local users to gain privileges via unknown vectors.

CVE-2011-2431
Adobe Reader and Acrobat 8.x before 8.3.1, 9.x before 9.4.6, and 10.x
before 10.1.1 allow attackers to execute arbitrary code via
unspecified vectors, related to a 'security bypass vulnerability.'

CVE-2011-2432
Buffer overflow in the U3D TIFF Resource in Adobe Reader and Acrobat
8.x before 8.3.1, 9.x before 9.4.6, and 10.x before 10.1.1 allows
attackers to execute arbitrary code via unspecified vectors.

CVE-2011-2433
Heap-based buffer overflow in Adobe Reader and Acrobat 8.x before
8.3.1, 9.x before 9.4.6, and 10.x before 10.1.1 allows attackers to
execute arbitrary code via unspecified vectors, a different
vulnerability than CVE-2011-2434 and CVE-2011-2437.

CVE-2011-2434
Heap-based buffer overflow in Adobe Reader and Acrobat 8.x before
8.3.1, 9.x before 9.4.6, and 10.x before 10.1.1 allows attackers to
execute arbitrary code via unspecified vectors, a different
vulnerability than CVE-2011-2433 and CVE-2011-2437.

CVE-2011-2435
Buffer overflow in Adobe Reader and Acrobat 8.x before 8.3.1, 9.x
before 9.4.6, and 10.x before 10.1.1 allows attackers to execute
arbitrary code via unspecified vectors.

CVE-2011-2436
Heap-based buffer overflow in the image-parsing library in Adobe
Reader and Acrobat 8.x before 8.3.1, 9.x before 9.4.6, and 10.x before
10.1.1 allows attackers to execute arbitrary code via unspecified
vectors.

CVE-2011-2437
Heap-based buffer overflow in Adobe Reader and Acrobat 8.x before
8.3.1, 9.x before 9.4.6, and 10.x before 10.1.1 allows attackers to
execute arbitrary code via unspecified vectors, a different
vulnerability than CVE-2011-2433 and CVE-2011-2434.

CVE-2011-2438
Multiple stack-based buffer overflows in the image-parsing library in
Adobe Reader and Acrobat 8.x before 8.3.1, 9.x before 9.4.6, and 10.x
before 10.1.1 allow attackers to execute arbitrary code via
unspecified vectors.

CVE-2011-2439
Adobe Reader and Acrobat 8.x before 8.3.1, 9.x before 9.4.6, and 10.x
before 10.1.1 allow attackers to execute arbitrary code via
unspecified vectors, related to a 'memory leakage condition
vulnerability.'

CVE-2011-2440
Use-after-free vulnerability in Adobe Reader and Acrobat 8.x before
8.3.1, 9.x before 9.4.6, and 10.x before 10.1.1 allows attackers to
execute arbitrary code via unspecified vectors.

CVE-2011-2441
Multiple stack-based buffer overflows in CoolType.dll in Adobe Reader
and Acrobat 8.x before 8.3.1, 9.x before 9.4.6, and 10.x before 10.1.1
allow attackers to execute arbitrary code via unspecified vectors.

CVE-2011-2442
Adobe Reader and Acrobat 8.x before 8.3.1, 9.x before 9.4.6, and 10.x
before 10.1.1 allow attackers to execute arbitrary code via
unspecified vectors, related to a 'logic error vulnerability.'";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.adobe.com/support/security/bulletins/apsb11-24.html
http://www.adobe.com/support/security/advisories/apsa11-04.html
http://www.vuxml.org/freebsd/fa2f386f-4814-11e1-89b4-001ec9578670.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70746");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-2462", "CVE-2011-1353", "CVE-2011-2431", "CVE-2011-2432", "CVE-2011-2433", "CVE-2011-2434", "CVE-2011-2435", "CVE-2011-2436", "CVE-2011-2437", "CVE-2011-2438", "CVE-2011-2439", "CVE-2011-2440", "CVE-2011-2441", "CVE-2011-2442");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)");
 script_name("FreeBSD Ports: acroread9");



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

txt = "";
vuln = 0;
txt = "";
bver = portver(pkg:"acroread9");
if(!isnull(bver) && revcomp(a:bver, b:"9.4.7")<0) {
    txt += 'Package acroread9 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
