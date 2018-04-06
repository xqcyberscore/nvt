#
#VID 91be81e7-3fea-11e1-afc7-2c4138874f7d
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 91be81e7-3fea-11e1-afc7-2c4138874f7d
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
   jruby
   ruby
   ruby+nopthreads
   ruby+nopthreads+oniguruma
   ruby+oniguruma
   rubygem-rack
   v8
   redis
   node

CVE-2011-4838
JRuby before 1.6.5.1 computes hash values without restricting the
ability to trigger hash collisions predictably, which allows
context-dependent attackers to cause a denial of service (CPU
consumption) via crafted input to an application that maintains a hash
table.

CVE-2011-4815
Ruby (aka CRuby) before 1.8.7-p357 computes hash values without
restricting the ability to trigger hash collisions predictably, which
allows context-dependent attackers to cause a denial of service (CPU
consumption) via crafted input to an application that maintains a hash
table.

CVE-2011-5036
Rack before 1.1.3, 1.2.x before 1.2.5, and 1.3.x before 1.3.6 computes
hash values for form parameters without restricting the ability to
trigger hash collisions predictably, which allows remote attackers to
cause a denial of service (CPU consumption) by sending many crafted
parameters.

CVE-2011-5037
Google V8 computes hash values for form parameters without restricting
the ability to trigger hash collisions predictably, which allows
remote attackers to cause a denial of service (CPU consumption) by
sending many crafted parameters, as demonstrated by attacks against
Node.js.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.ocert.org/advisories/ocert-2011-003.html
http://www.nruns.com/_downloads/advisory28122011.pdf
http://www.vuxml.org/freebsd/91be81e7-3fea-11e1-afc7-2c4138874f7d.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70754");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cve_id("CVE-2011-4838", "CVE-2011-4815", "CVE-2011-5036", "CVE-2011-5037");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)");
 script_name("FreeBSD Ports: jruby");



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
bver = portver(pkg:"jruby");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.5.1")<0) {
    txt += 'Package jruby version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ruby");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.7.357,1")<0) {
    txt += 'Package ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ruby+nopthreads");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.7.357,1")<0) {
    txt += 'Package ruby+nopthreads version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ruby+nopthreads+oniguruma");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.7.357,1")<0) {
    txt += 'Package ruby+nopthreads+oniguruma version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ruby+oniguruma");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.7.357,1")<0) {
    txt += 'Package ruby+oniguruma version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"rubygem-rack");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.6,3")<0) {
    txt += 'Package rubygem-rack version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"v8");
if(!isnull(bver) && revcomp(a:bver, b:"3.8.5")<0) {
    txt += 'Package v8 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"redis");
if(!isnull(bver) && revcomp(a:bver, b:"2.4.6")<=0) {
    txt += 'Package redis version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"node");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.7")<0) {
    txt += 'Package node version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
