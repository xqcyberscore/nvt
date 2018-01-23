###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for glibc CESA-2013:0769 centos5
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The glibc packages provide the standard C libraries (libc), POSIX thread
  libraries (libpthread), standard math libraries (libm), and the Name Server
  Caching Daemon (nscd) used by multiple programs on the system. Without
  these libraries, the Linux system cannot function correctly.

  It was found that getaddrinfo() did not limit the amount of stack memory
  used during name resolution. An attacker able to make an application
  resolve an attacker-controlled hostname or IP address could possibly cause
  the application to exhaust all stack memory and crash. (CVE-2013-1914)

  A flaw was found in the regular expression matching routines that process
  multibyte character input. If an application utilized the glibc regular
  expression matching mechanism, an attacker could provide specially-crafted
  input that, when processed, would cause the application to crash.
  (CVE-2013-0242)

  This update also fixes the following bugs:

  * The improvements RHSA-2012:1207 made to the accuracy of floating point
  functions in the math library caused performance regressions for those
  functions. The performance regressions were analyzed and a fix was applied
  that retains the current accuracy but reduces the performance penalty to
  acceptable levels. Refer to Red Hat Knowledge solution 229993, linked
  to in the References, for further information. (BZ#950535)

  * It was possible that a memory location freed by the localization code
  could be accessed immediately after, resulting in a crash. The fix ensures
  that the application does not crash by avoiding the invalid memory access.
  (BZ#951493)

  Users of glibc are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.

  4. Solution:

  Before applying this update, make sure all previously-released errata
  relevant to your system have been applied.

  This update is available via the Red Hat Network. Details on how to
  use the Red Hat Network to apply this update are available at
  https://access.redhat.com/knowledge/articles/11258

  5. Bugs fixed (http://bugzilla.redhat.com):

  905874 - CVE-2013-0242 glibc: Buffer overrun (DoS) in regexp matcher
           by processing multibyte characters
  947882 - CVE-2013-1914 glibc: Stack (frame) overflow in getaddrinfo()
           when processing entry mapping to long list of address structures

  6. Package List:

  Red Hat Enterprise Linux Desktop (v. 5 client):

  Source: ...

  Description truncated, for more information please check the Reference URL";


tag_solution = "Please Install the Updated Packages.";
tag_affected = "glibc on CentOS 5";


if(description)
{
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_id(881722);
  script_version("$Revision: 8483 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 07:58:04 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-04-25 10:23:03 +0530 (Thu, 25 Apr 2013)");
  script_cve_id("CVE-2013-0242", "CVE-2013-1914");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("CentOS Update for glibc CESA-2013:0769 centos5 ");

  script_xref(name: "CESA", value: "2013:0769");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-April/019706.html");
  script_tag(name: "summary" , value: "Check for the Version of glibc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.5~107.el5_9.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.5~107.el5_9.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.5~107.el5_9.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.5~107.el5_9.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.5~107.el5_9.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.5~107.el5_9.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
