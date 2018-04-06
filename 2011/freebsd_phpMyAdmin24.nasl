#
#VID d79fc873-b5f9-11e0-89b4-001ec9578670
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID d79fc873-b5f9-11e0-89b4-001ec9578670
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
tag_insight = "The following package is affected: phpMyAdmin

CVE-2011-2642
Multiple cross-site scripting (XSS) vulnerabilities in the table Print
view implementation in tbl_printview.php in phpMyAdmin before 3.3.10.3
and 3.4.x before 3.4.3.2 allow remote authenticated users to inject
arbitrary web script or HTML via a crafted table name.

CVE-2011-2643
Directory traversal vulnerability in sql.php in phpMyAdmin 3.4.x
before 3.4.3.2, when configuration storage is enabled, allows remote
attackers to include and execute arbitrary local files via directory
traversal sequences in a MIME-type transformation parameter.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.phpmyadmin.net/home_page/security/PMASA-2011-9.php
http://www.phpmyadmin.net/home_page/security/PMASA-2011-10.php
http://www.phpmyadmin.net/home_page/security/PMASA-2011-11.php
http://www.phpmyadmin.net/home_page/security/PMASA-2011-12.php
http://www.vuxml.org/freebsd/d79fc873-b5f9-11e0-89b4-001ec9578670.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70063");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-08-07 17:37:07 +0200 (Sun, 07 Aug 2011)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-2642", "CVE-2011-2643");
 script_name("FreeBSD Ports: phpMyAdmin");



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
bver = portver(pkg:"phpMyAdmin");
if(!isnull(bver) && revcomp(a:bver, b:"3.4.3.2")<0) {
    txt += 'Package phpMyAdmin version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
