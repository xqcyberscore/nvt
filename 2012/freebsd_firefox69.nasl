#
#VID 2b8cad90-f289-11e1-a215-14dae9ebcf89
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 2b8cad90-f289-11e1-a215-14dae9ebcf89
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
   firefox
   linux-firefox
   linux-seamonkey
   linux-thunderbird
   seamonkey
   thunderbird
   libxul";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.mozilla.org/security/known-vulnerabilities/
http://www.mozilla.org/security/announce/2012/mfsa2012-57.html
http://www.mozilla.org/security/announce/2012/mfsa2012-58.html
http://www.mozilla.org/security/announce/2012/mfsa2012-59.html
http://www.mozilla.org/security/announce/2012/mfsa2012-60.html
http://www.mozilla.org/security/announce/2012/mfsa2012-61.html
http://www.mozilla.org/security/announce/2012/mfsa2012-62.html
http://www.mozilla.org/security/announce/2012/mfsa2012-63.html
http://www.mozilla.org/security/announce/2012/mfsa2012-64.html
http://www.mozilla.org/security/announce/2012/mfsa2012-65.html
http://www.mozilla.org/security/announce/2012/mfsa2012-66.html
http://www.mozilla.org/security/announce/2012/mfsa2012-67.html
http://www.mozilla.org/security/announce/2012/mfsa2012-68.html
http://www.mozilla.org/security/announce/2012/mfsa2012-69.html
http://www.mozilla.org/security/announce/2012/mfsa2012-70.html
http://www.mozilla.org/security/announce/2012/mfsa2012-71.html
http://www.mozilla.org/security/announce/2012/mfsa2012-72.html
http://www.vuxml.org/freebsd/2b8cad90-f289-11e1-a215-14dae9ebcf89.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71829");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-1956", "CVE-2012-1970", "CVE-2012-1971", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974", "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3956", "CVE-2012-3957", "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961", "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3965", "CVE-2012-3966", "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970", "CVE-2012-3971", "CVE-2012-3972", "CVE-2012-3973", "CVE-2012-3974", "CVE-2012-3975", "CVE-2012-3976", "CVE-2012-3978", "CVE-2012-3979", "CVE-2012-3980");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-08-30 11:34:17 -0400 (Thu, 30 Aug 2012)");
 script_name("FreeBSD Ports: firefox");


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
bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"11.0,1")>0 && revcomp(a:bver, b:"15.0,1")<0) {
    txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.7,1")<0) {
    txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.7,1")<0) {
    txt += "Package linux-firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.12")<0) {
    txt += "Package linux-seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.7")<0) {
    txt += "Package linux-thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.12")<0) {
    txt += "Package seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"11.0")>0 && revcomp(a:bver, b:"15.0")<0) {
    txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.7")<0) {
    txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"libxul");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.2")>0 && revcomp(a:bver, b:"10.0.7")<0) {
    txt += "Package libxul version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
