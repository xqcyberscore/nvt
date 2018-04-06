# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2006_200_01.nasl 9352 2018-04-06 07:13:02Z cfischer $
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
tag_insight = "New Samba packages are available for Slackware 10.0, 10.1, 10.2,
and -current.

In Slackware 10.0, 10.1, and 10.2, Samba was evidently picking up
the libdm.so.0 library causing a Samba package issued primarily as
a security patch to suddenly require a library that would only be
present on the machine if the xfsprogs package (from the A series
but marked 'optional') was installed.  Sorry -- this was not
intentional, though I do know that I'm taking the chance of this
kind of issue when trying to get security related problems fixed
quickly (hopefully balanced with reasonable testing), and when the
fix is achieved by upgrading to a new version rather than with the
smallest patch possible to fix the known issue.  However, I tend
to trust that by following upstream sources as much as possible
I'm also fixing some problems that aren't yet public.

So, all of the the 10.0, 10.1, and 10.2 packages have been rebuilt
on systems without the dm library, and should be able to directly
upgrade older samba packages without additional requirements.
Well, unless they are also under /patches.

All the packages (including -current) have been patched with a
fix from Samba's CVS for some reported problems with winbind.
Thanks to Mikhail Kshevetskiy for pointing me to the patch.

I realize these packages don't really fix security issues, but
they do fix security patch packages that are less than a couple
of days old, so it seems prudent to notify slackware-security
(and any subscribed lists) again.  Sorry if it's noise...";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2006-200-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2006-200-01";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.57174");
 script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_version("$Revision: 9352 $");
 name = "Slackware Advisory SSA:2006-200-01 Samba 2.0.23 repackaged ";
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
if(isslkpkgvuln(pkg:"samba", ver:"3.0.23-i486-2_slack10.0", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"samba", ver:"3.0.23-i486-2_slack10.1", rls:"SLK10.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"samba", ver:"3.0.23-i486-2_slack10.2", rls:"SLK10.2")) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
