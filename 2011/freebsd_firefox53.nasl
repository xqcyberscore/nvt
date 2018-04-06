#
#VID 1d8ff4a2-0445-11e0-8e32-000f20797ede
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 1d8ff4a2-0445-11e0-8e32-000f20797ede
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
   libxul
   linux-firefox
   linux-firefox-devel
   linux-seamonkey
   linux-thunderbird
   seamonkey
   thunderbird

For details, please visit the referenced security advisories.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.mozilla.org/security/announce/2010/mfsa2010-74.html
http://www.mozilla.org/security/announce/2010/mfsa2010-75.html
http://www.mozilla.org/security/announce/2010/mfsa2010-76.html
http://www.mozilla.org/security/announce/2010/mfsa2010-77.html
http://www.mozilla.org/security/announce/2010/mfsa2010-78.html
http://www.mozilla.org/security/announce/2010/mfsa2010-79.html
http://www.mozilla.org/security/announce/2010/mfsa2010-80.html
http://www.mozilla.org/security/announce/2010/mfsa2010-81.html
http://www.mozilla.org/security/announce/2010/mfsa2010-82.html
http://www.mozilla.org/security/announce/2010/mfsa2010-83.html
http://www.mozilla.org/security/announce/2010/mfsa2010-84.html
http://www.vuxml.org/freebsd/1d8ff4a2-0445-11e0-8e32-000f20797ede.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.68690");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-3766", "CVE-2010-3767", "CVE-2010-3768", "CVE-2010-3769", "CVE-2010-3770", "CVE-2010-3771", "CVE-2010-3772", "CVE-2010-3773", "CVE-2010-3774", "CVE-2010-3775", "CVE-2010-3776", "CVE-2010-3777", "CVE-2010-3778");
 script_name("FreeBSD Ports: firefox");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"3.6.*,1")>0 && revcomp(a:bver, b:"3.6.13,1")<0) {
    txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.5.*,1")>0 && revcomp(a:bver, b:"3.5.16,1")<0) {
    txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"libxul");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.2")>0 && revcomp(a:bver, b:"1.9.2.13")<0) {
    txt += 'Package libxul version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"3.6.13,1")<0) {
    txt += 'Package linux-firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-firefox-devel");
if(!isnull(bver) && revcomp(a:bver, b:"3.5.16")<0) {
    txt += 'Package linux-firefox-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>0 && revcomp(a:bver, b:"2.0.11")<0) {
    txt += 'Package linux-seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"3.1")>=0 && revcomp(a:bver, b:"3.1.7")<0) {
    txt += 'Package linux-thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>0 && revcomp(a:bver, b:"2.0.11")<0) {
    txt += 'Package seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"3.0")>=0 && revcomp(a:bver, b:"3.0.11")<0) {
    txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.1")>=0 && revcomp(a:bver, b:"3.1.7")<0) {
    txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
