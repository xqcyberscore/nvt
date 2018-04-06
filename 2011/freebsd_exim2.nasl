#
#VID 44ccfab0-3564-11e0-8e81-0022190034c0
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 44ccfab0-3564-11e0-8e81-0022190034c0
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
   exim
   exim-ldap
   exim-ldap2
   exim-mysql
   exim-postgresql
   exim-sa-exim

CVE-2011-0017
The open_log function in log.c in Exim 4.72 and earlier does not check
the return value from (1) setuid or (2) setgid system calls, which
allows local users to append log data to arbitrary files via a symlink
attack.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

ftp://ftp.exim.org/pub/exim/ChangeLogs/ChangeLog-4.74
http://www.vuxml.org/freebsd/44ccfab0-3564-11e0-8e81-0022190034c0.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.68948");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-05 22:25:39 +0100 (Sat, 05 Mar 2011)");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0017");
 script_name("exim -- local privilege escalation");



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
bver = portver(pkg:"exim");
if(!isnull(bver) && revcomp(a:bver, b:"4.74")<0) {
    txt += 'Package exim version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"exim-ldap");
if(!isnull(bver) && revcomp(a:bver, b:"4.74")<0) {
    txt += 'Package exim-ldap version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"exim-ldap2");
if(!isnull(bver) && revcomp(a:bver, b:"4.74")<0) {
    txt += 'Package exim-ldap2 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"exim-mysql");
if(!isnull(bver) && revcomp(a:bver, b:"4.74")<0) {
    txt += 'Package exim-mysql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"exim-postgresql");
if(!isnull(bver) && revcomp(a:bver, b:"4.74")<0) {
    txt += 'Package exim-postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"exim-sa-exim");
if(!isnull(bver) && revcomp(a:bver, b:"4.74")<0) {
    txt += 'Package exim-sa-exim version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
