###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for glibc CESA-2014:1110 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881990");
  script_version("$Revision: 9373 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:57:18 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-08-30 05:51:00 +0200 (Sat, 30 Aug 2014)");
  script_cve_id("CVE-2014-0475", "CVE-2014-5119");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for glibc CESA-2014:1110 centos6 ");

  tag_insight = "The glibc packages contain the standard C libraries used by
multiple programs on the system. These packages contain the standard C and the
standard math libraries. Without these two libraries, a Linux system cannot
function properly.

An off-by-one heap-based buffer overflow flaw was found in glibc's internal
__gconv_translit_find() function. An attacker able to make an application
call the iconv_open() function with a specially crafted argument could
possibly use this flaw to execute arbitrary code with the privileges of
that application. (CVE-2014-5119)

A directory traveral flaw was found in the way glibc loaded locale files.
An attacker able to make an application use a specially crafted locale name
value (for example, specified in an LC_* environment variable) could
possibly use this flaw to execute arbitrary code with the privileges of
that application. (CVE-2014-0475)

Red Hat would like to thank Stephane Chazelas for reporting CVE-2014-0475.

All glibc users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.

4. Solution:

Before applying this update, make sure all previously released errata
relevant to your system have been applied.

This update is available via the Red Hat Network. Details on how to use the
Red Hat Network to apply this update are available at
https://access.redhat.com/articles/11258

5. Bugs fixed (https://bugzilla.redhat.com/):

1102353 - CVE-2014-0475 glibc: directory traversal in LC_* locale handling
1119128 - CVE-2014-5119 glibc: off-by-one error leading to a heap-based buffer overflow flaw in __gconv_translit_find()

6. Package List:

Red Hat Enterprise Linux Desktop (v. 5 client):

Source:
glibc-2.5-118.el5_10.3.src.rpm

i386:
glibc-2.5-118.el5_10.3.i386.rpm
glibc-2.5-118.el5_10.3.i686.rpm
glibc-common-2.5-118.el5_10.3.i386.rpm
glibc-debuginfo-2.5-118.el5_10.3.i386.rpm
glibc-debuginfo-2.5-118.el5_10.3.i686.rpm
glibc-debuginfo-common-2.5-118.el5_10.3.i386.rpm
glibc-devel-2.5-118.el5_10.3.i386.rpm
glibc-headers-2.5-118.el5_10.3.i386.rpm
glibc-utils-2.5-118.el5_10.3.i386.rpm
nscd-2.5-118.el5_10.3.i386.rpm

x86_64:
glibc-2.5-118.el5_10.3.i686.rpm
glibc-2.5-118.el5_10.3.x86_64.rpm
glibc-common-2.5-118.el5_10.3.x86_64.rpm
glibc-debuginfo-2.5-118.el5_10.3.i386.rpm
glibc-debuginfo-2.5-118.el5_10.3.i686.rpm
glibc-debuginfo-2.5-118.el5_10.3.x86_64.rpm
glibc-debuginfo-common-2.5-118.el5_10.3.i386.rpm
glibc-devel-2.5-118.el5_10.3.i386.rpm
glibc-devel-2.5-118.el5_10.3.x86_64.rpm
glibc-headers-2 ...

  Description truncated, for more information please check the Reference URL";

  tag_affected = "glibc on CentOS 6";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2014:1110");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2014-August/020518.html");
  script_tag(name:"summary", value:"Check for the Version of glibc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.12~1.132.el6_5.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.12~1.132.el6_5.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.12~1.132.el6_5.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.12~1.132.el6_5.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-static", rpm:"glibc-static~2.12~1.132.el6_5.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.12~1.132.el6_5.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.12~1.132.el6_5.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
