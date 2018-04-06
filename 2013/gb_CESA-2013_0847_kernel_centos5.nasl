###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2013:0847 centos5
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

  * A flaw was found in the way the Xen hypervisor AMD IOMMU driver handled
  interrupt remapping entries. By default, a single interrupt remapping
  table is used, and old interrupt remapping entries are not cleared,
  potentially allowing a privileged guest user in a guest that has a
  passed-through, bus-mastering capable PCI device to inject interrupt
  entries into others guests, including the privileged management domain
  (Dom0), leading to a denial of service. (CVE-2013-0153, Moderate)

  Red Hat would like to thank the Xen project for reporting the CVE-2013-0153
  issue.

  This update also fixes the following bugs:

  * When a process is opening a file over NFSv4, sometimes an OPEN call can
  succeed while the following GETATTR operation fails with an NFS4ERR_DELAY
  error. The NFSv4 code did not handle such a situation correctly and allowed
  an NFSv4 client to attempt to use the buffer that should contain the
  GETATTR information. However, the buffer did not contain the valid GETATTR
  information, which caused the client to return a &quot;-ENOTDIR&quot; error.
  Consequently, the process failed to open the requested file. This update
  backports a patch that adds a test condition verifying validity of the
  GETATTR information. If the GETATTR information is invalid, it is obtained
  later and the process opens the requested file as expected. (BZ#947736)

  * Previously, the xdr routines in NFS version 2 and 3 conditionally updated
  the res-&gt;count variable. Read retry attempts after a short NFS read() call
  could fail to update the res-&gt;count variable, resulting in truncated read
  data being returned. With this update, the res-&gt;count variable is updated
  unconditionally so this bug can no longer occur. (BZ#952098)

  * When handling requests from Intelligent Platform Management Interface
  (IPMI) clients, the IPMI driver previously used two different locks for an
  IPMI request. If two IPMI clients sent their requests at the same time,
  each request could receive one of the locks and then wait for the second
  lock to become available. This resulted in a deadlock situation and the
  system became unresponsive. The problem could occur more likely in
  environments with many IPMI clients. This update modifies the IPMI driver
  to handle the received messages using tasklets so the driver now uses a
  safe locking technique when handling IPMI requests and the mentioned
  deadlock can no longer occur. (BZ#953435)

  * In ...

  Description truncated, for more information please check the Reference URL";


tag_affected = "kernel on CentOS 5";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881737");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-05-23 09:54:54 +0530 (Thu, 23 May 2013)");
  script_cve_id("CVE-2013-0153");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_name("CentOS Update for kernel CESA-2013:0847 centos5 ");

  script_xref(name: "CESA", value: "2013:0847");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-May/019735.html");
  script_tag(name: "summary" , value: "Check for the Version of kernel");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~348.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~348.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~348.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~348.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~348.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~348.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~348.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~348.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~348.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~348.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
