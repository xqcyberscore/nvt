# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2003_251_01.nasl 9352 2018-04-06 07:13:02Z cfischer $
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
tag_insight = "Upgraded inetd packages are available for Slackware 8.1, 9.0 and
- -current.  These fix a previously hard-coded limit of 256
connections-per-minute, after which the given service is disabled
for ten minutes.  An attacker could use a quick burst of
connections every ten minutes to effectively disable a service.

Once upon a time, this was an intentional feature of inetd, but in
today's world it has become a bug.  Even having inetd look at the
source IP and try to limit only the source of the attack would be
problematic since TCP source addresses are so easily faked.  So,
the approach we have taken (borrowed from FreeBSD) is to disable
this rate limiting 'feature' by default.  It can be reenabled by
providing a -R <rate> option on the command-line if desired, but
for obvious reasons we do not recommend this.

Any site running services through inetd that they would like
protected from this simple DoS attack should upgrade to the new
inetd package immediately.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2003-251-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2003-251-01";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.53887");
 script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_version("$Revision: 9352 $");
 name = "Slackware Advisory SSA:2003-251-01 inetd DoS patched ";
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
if(isslkpkgvuln(pkg:"inetd", ver:"1.79s-i386-2", rls:"SLK8.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"inetd", ver:"1.79s-i386-2", rls:"SLK9.0")) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
