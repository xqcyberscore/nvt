# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2006_142_01.nasl 5356 2017-02-20 10:49:58Z cfi $
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
tag_insight = "New tetex packages are available for Slackware 10.2 and -current to
fix a possible security issue.  teTeX-3.0 incorporates some code from
the xpdf program which has been shown to have various overflows that
could result in program crashes or possibly the execution of arbitrary
code as the teTeX user.  This is especially important to consider if
teTeX is being used as part of a printer filter.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3193";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2006-142-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2006-142-01";
                                                                                
if(description)
{
 script_id(56793);
 script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
 script_tag(name:"last_modification", value:"$Date: 2017-02-20 11:49:58 +0100 (Mon, 20 Feb 2017) $");
 script_bugtraq_id(15721);
 script_cve_id("CVE-2005-3193");
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_version("$Revision: 5356 $");
 name = "Slackware Advisory SSA:2006-142-01 tetex PDF security ";
 script_name(name);


 script_summary("Slackware Advisory SSA:2006-142-01 tetex PDF security");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Slackware Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success", "ssh/login/slackpack");
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
if(isslkpkgvuln(pkg:"tetex", ver:"3.0-i486-2_10.2", rls:"SLK10.2")) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
