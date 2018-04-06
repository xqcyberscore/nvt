#
#VID 8b986a05-4dbe-11e0-8b9a-02e0184b8d35
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 8b986a05-4dbe-11e0-8b9a-02e0184b8d35
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
tag_insight = "The following packages are affected:
   avahi
   avahi-app
   avahi-autoipd
   avahi-gtk
   avahi-libdns
   avahi-qt3
   avahi-qt4
   avahi-sharp

CVE-2011-1002
avahi-core/socket.c in avahi-daemon in Avahi before 0.6.29 allows
remote attackers to cause a denial of service (infinite loop) via an
empty (1) IPv4 or (2) IPv6 UDP packet to port 5353.  NOTE: this
vulnerability exists because of an incorrect fix for CVE-2010-2244.

CVE-2010-2244
The AvahiDnsPacket function in avahi-core/socket.c in avahi-daemon in
Avahi 0.6.16 and 0.6.25 allows remote attackers to cause a denial of
service (assertion failure and daemon exit) via a DNS packet with an
invalid checksum followed by a DNS packet with a valid checksum, a
different vulnerability than CVE-2008-5081.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/43361/
https://bugzilla.redhat.com/show_bug.cgi?id=667187
http://www.vuxml.org/freebsd/8b986a05-4dbe-11e0-8b9a-02e0184b8d35.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69366");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2011-1002", "CVE-2010-2244");
 script_name("avahi -- denial of service");



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
bver = portver(pkg:"avahi");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
    txt += 'Package avahi version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"avahi-app");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
    txt += 'Package avahi-app version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"avahi-autoipd");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
    txt += 'Package avahi-autoipd version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"avahi-gtk");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
    txt += 'Package avahi-gtk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"avahi-libdns");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
    txt += 'Package avahi-libdns version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"avahi-qt3");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
    txt += 'Package avahi-qt3 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"avahi-qt4");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
    txt += 'Package avahi-qt4 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"avahi-sharp");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.29")<0) {
    txt += 'Package avahi-sharp version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
