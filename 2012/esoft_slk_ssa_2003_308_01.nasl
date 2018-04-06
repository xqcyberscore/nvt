# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2003_308_01.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from the corresponding slackware advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
tag_insight = "Apache httpd is a hypertext transfer protocol server, and is used
by over two thirds of the Internet's web sites.

Upgraded Apache packages are available for Slackware 8.1, 9.0, 9.1,
and -current.  These fix local vulnerabilities that could allow users
who can create or edit Apache config files to gain additional
privileges.  Sites running Apache should upgrade to the new packages.

In addition, new mod_ssl packages have been prepared for all platforms,
and new PHP packages have been prepared for Slackware 8.1, 9.0, and
- -current (9.1 already uses PHP 4.3.3).  In -current, these packages
also move the Apache module directory from /usr/libexec to
/usr/libexec/apache.  Links for all of these related packages are
provided below.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2003-308-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2003-308-01";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.53878");
 script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_bugtraq_id(9504, 8911);
 script_cve_id("CVE-2003-0542");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 9352 $");
 name = "Slackware Advisory SSA:2003-308-01 apache security update ";
 script_name(name);



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Slackware Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-slack.inc");
vuln = 0;
if(isslkpkgvuln(pkg:"apache", ver:"1.3.29-i386-1", rls:"SLK8.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.16_1.3.29-i386-1", rls:"SLK8.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"php", ver:"4.3.3-i386-1", rls:"SLK8.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"apache", ver:"1.3.29-i386-1", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.16_1.3.29-i386-1", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"php", ver:"4.3.3-i386-1", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"apache", ver:"1.3.29-i486-1", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.16_1.3.29-i486-1", rls:"SLK9.1")) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
