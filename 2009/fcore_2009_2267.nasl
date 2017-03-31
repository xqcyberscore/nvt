# OpenVAS Vulnerability Test
# $Id: fcore_2009_2267.nasl 4691 2016-12-06 15:40:14Z teissa $
# Description: Auto-generated from advisory FEDORA-2009-2267 (opensc)
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

Security update fixing CVE-2008-3972, CVE-2008-2235, and CVE-2009-0368.
ChangeLog:

* Fri Feb 27 2009 Tomas Mraz  - 0.11.7-1
- new upstream version - fixes CVE-2009-0368
* Thu Feb 26 2009 Fedora Release Engineering  - 0.11.6-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update opensc' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2267";
tag_summary = "The remote host is missing an update to opensc
announced via advisory FEDORA-2009-2267.";



if(description)
{
 script_id(63601);
 script_version("$Revision: 4691 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-06 16:40:14 +0100 (Tue, 06 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
 script_cve_id("CVE-2008-3972", "CVE-2008-2235", "CVE-2009-0368");
 script_tag(name:"cvss_base", value:"6.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:C");
 script_name("Fedora Core 9 FEDORA-2009-2267 (opensc)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=487694");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=457367");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"mozilla-opensc-signer", rpm:"mozilla-opensc-signer~0.11.7~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.11.7~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"opensc-devel", rpm:"opensc-devel~0.11.7~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"opensc-debuginfo", rpm:"opensc-debuginfo~0.11.7~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
