#CESA-2009:0313 63569 8
# $Id: ovcesa2009_0313.nasl 5002 2017-01-13 10:17:13Z teissa $
# Description: Auto-generated from advisory CESA-2009:0313 (wireshark)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "For details on the issues addressed in this update,
please visit the referenced security advisories.";
tag_solution = "Update the appropriate packages on your system.

http://www.securityspace.com/smysecure/catid.html?in=CESA-2009:0313
http://www.securityspace.com/smysecure/catid.html?in=RHSA-2009:0313
https://rhn.redhat.com/errata/RHSA-2009-0313.html";
tag_summary = "The remote host is missing updates to wireshark announced in
advisory CESA-2009:0313.";



if(description)
{
 script_id(63569);
 script_version("$Revision: 5002 $");
 script_tag(name:"last_modification", value:"$Date: 2017-01-13 11:17:13 +0100 (Fri, 13 Jan 2017) $");
 script_tag(name:"creation_date", value:"2009-03-13 19:24:56 +0100 (Fri, 13 Mar 2009)");
 script_cve_id("CVE-2008-4680", "CVE-2008-4681", "CVE-2008-4682", "CVE-2008-4683", "CVE-2008-4684", "CVE-2008-4685", "CVE-2008-5285", "CVE-2009-0599", "CVE-2009-0600");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("CentOS Security Advisory CESA-2009:0313 (wireshark)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("CentOS Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/rpms");
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

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.0.6~EL3.3", rls:"CentOS3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.0.6~EL3.3", rls:"CentOS3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.0.6~2.el4_7", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.0.6~2.el4_7", rls:"CentOS4")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
