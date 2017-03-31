# OpenVAS Vulnerability Test
# $Id: fcore_2009_1373.nasl 4691 2016-12-06 15:40:14Z teissa $
# Description: Auto-generated from advisory FEDORA-2009-1373 (java-1.6.0-openjdk)
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
tag_insight = "The OpenJDK runtime environment.

Update Information:

This fixes a default security policy, that allowed unsigned applets to access
the gnome-java-bridge, allowing a privilege escalation (#474431).    There are
also several bug fixes included in this update.";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update java-1.6.0-openjdk' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1373";
tag_summary = "The remote host is missing an update to java-1.6.0-openjdk
announced via advisory FEDORA-2009-1373.";



if(description)
{
 script_id(63376);
 script_version("$Revision: 4691 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-06 16:40:14 +0100 (Tue, 06 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_name("Fedora Core 10 FEDORA-2009-1373 (java-1.6.0-openjdk)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=476462");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=452573");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=475109");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=472953");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=475081");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=474431");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=474503");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=472862");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~9.b14.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~demo~1.6.0.0", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~devel~1.6.0.0", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~javadoc~1.6.0.0", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~plugin~1.6.0.0", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~src~1.6.0.0", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~debuginfo~1.6.0.0", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
