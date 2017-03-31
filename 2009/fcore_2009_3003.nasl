# OpenVAS Vulnerability Test
# $Id: fcore_2009_3003.nasl 4691 2016-12-06 15:40:14Z teissa $
# Description: Auto-generated from advisory FEDORA-2009-3003 (compiz-fusion)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Update Information:

This update fixes a security issue in the expo plugin which allows local users
with physical access to drag the screen saver aside and access the locked
desktop by using Expo mouse shortcuts.
ChangeLog:

* Tue Mar 24 2009 Adel Gadllah  0.7.6-6
- Add fix for RH #491918, CVE-2008-6514
* Sat Mar 14 2009 Adel Gadllah  0.7.6-5
- Backport upstream fix for RH #474741";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update compiz-fusion' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3003";
tag_summary = "The remote host is missing an update to compiz-fusion
announced via advisory FEDORA-2009-3003.";



if(description)
{
 script_id(63669);
 script_version("$Revision: 4691 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-06 16:40:14 +0100 (Tue, 06 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
 script_cve_id("CVE-2008-6514");
 script_tag(name:"cvss_base", value:"6.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
 script_name("Fedora Core 9 FEDORA-2009-3003 (compiz-fusion)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Fedora Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/rpms");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=491918");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"compiz-fusion", rpm:"compiz-fusion~0.7.6~6.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compiz-fusion-devel", rpm:"compiz-fusion-devel~0.7.6~6.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compiz-fusion-gnome", rpm:"compiz-fusion-gnome~0.7.6~6.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compiz-fusion-debuginfo", rpm:"compiz-fusion-debuginfo~0.7.6~6.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
