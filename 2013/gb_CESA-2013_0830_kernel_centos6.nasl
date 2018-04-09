###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2013:0830 centos6
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
tag_insight = "The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issue:

  * It was found that the Red Hat Enterprise Linux 6.1 kernel update
  (RHSA-2011:0542) introduced an integer conversion issue in the Linux
  kernel's Performance Events implementation. This led to a user-supplied
  index into the perf_swevent_enabled array not being validated properly,
  resulting in out-of-bounds kernel memory access. A local, unprivileged user
  could use this flaw to escalate their privileges. (CVE-2013-2094,
  Important)

  A public exploit that affects Red Hat Enterprise Linux 6 is available.

  Refer to Red Hat Knowledge Solution 373743, linked to in the References,
  for further information and mitigation instructions for users who are
  unable to immediately apply this update.

  Users should upgrade to these updated packages, which contain a backported
  patch to correct this issue. The system must be rebooted for this update to
  take effect.

  4. Solution:

  Before applying this update, make sure all previously-released errata
  relevant to your system have been applied.

  This update is available via the Red Hat Network. Details on how to
  use the Red Hat Network to apply this update are available at
  https://access.redhat.com/knowledge/articles/11258

  To install kernel packages manually, use &quot;rpm -ivh [package] Do not
  use rpm -Uvh as that will remove the running kernel binaries from
  your system. You may use rpm -e to remove old kernels after
  determining that the new kernel functions properly on your system.

  5. Bugs fixed (http://bugzilla.redhat.com):

  962792 - CVE-2013-2094 kernel: perf_swevent_enabled array out-of-bound access

  6. Package List:

  Red Hat Enterprise Linux Desktop (v. 6):

  Source:
  ftp://ftp.redhat.com/pub/redhat/linux/enterprise/6Client/en/os/SRPMS/kernel-2.6.32-358.6.2.el6.src.rpm

  i386:
  kernel-2.6.32-358.6.2.el6.i686.rpm
  kernel-debug-2.6.32-358.6.2.el6.i686.rpm
  kernel-debug-debuginfo-2.6.32-358.6.2.el6.i686.rpm
  kernel-debug-devel-2.6.32-358.6.2.el6.i686.rpm
  kernel-debuginfo-2.6.32-358.6.2.el6.i686.rpm
  kernel-debuginfo-common-i686-2.6.32-358.6.2.el6.i686.rpm
  kernel-devel-2.6.32-358.6.2.el6.i ...

  Description truncated, for more information please check the Reference URL";


tag_affected = "kernel on CentOS 6";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881731");
  script_version("$Revision: 9372 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:56:37 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-05-17 09:53:11 +0530 (Fri, 17 May 2013)");
  script_cve_id("CVE-2013-2094");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for kernel CESA-2013:0830 centos6 ");

  script_xref(name: "CESA", value: "2013:0830");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-May/019733.html");
  script_tag(name:"summary", value:"Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.6.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.6.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.6.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.6.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.6.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.6.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.6.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.6.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.6.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
