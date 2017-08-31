###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for spice-server RHSA-2015:1715-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871446");
  script_version("$Revision: 6689 $");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:50:06 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-09-04 08:13:20 +0200 (Fri, 04 Sep 2015)");
  script_cve_id("CVE-2015-3247");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for spice-server RHSA-2015:1715-01");
  script_tag(name: "summary", value: "Check the version of spice-server");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The Simple Protocol for Independent Computing Environments (SPICE) is a
remote display protocol for virtual environments. SPICE users can access a
virtualized desktop or server from the local system or any system with
network access to the server. SPICE is used in Red Hat Enterprise Linux for
viewing virtualized guests running on the Kernel-based Virtual Machine
(KVM) hypervisor or on Red Hat Enterprise Virtualization Hypervisors.

A race condition flaw, leading to a heap-based memory corruption, was found
in spice's worker_update_monitors_config() function, which runs under the
QEMU-KVM context on the host. A user in a guest could leverage this flaw to
crash the host QEMU-KVM process or, possibly, execute arbitrary code with
the privileges of the host QEMU-KVM process. (CVE-2015-3247)

This issue was discovered by Frediano Ziglio of Red Hat.

All spice-server users are advised to upgrade to this updated package,
which contains a backported patch to correct this issue.
");
  script_tag(name: "affected", value: "spice-server on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "RHSA", value: "2015:1715-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2015-September/msg00010.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"spice-server", rpm:"spice-server~0.12.4~12.el6_7.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-server-debuginfo", rpm:"spice-server-debuginfo~0.12.4~12.el6_7.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
