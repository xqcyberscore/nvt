###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for qemu-guest-agent CESA-2013:1100 centos6 
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
tag_insight = "KVM (Kernel-based Virtual Machine) is a full virtualization solution for
Linux on AMD64 and Intel 64 systems. qemu-kvm is the user-space component
for running virtual machines using KVM.

An unquoted search path flaw was found in the way the QEMU Guest Agent
service installation was performed on Windows. Depending on the permissions
of the directories in the unquoted search path, a local, unprivileged user
could use this flaw to have a binary of their choosing executed with SYSTEM
privileges. (CVE-2013-2231)

This issue was discovered by Lev Veyde of Red Hat.

All users of qemu-kvm should upgrade to these updated packages, which
contain backported patches to correct this issue. After installing this
update, shut down all running virtual machines. Once all virtual machines
have shut down, start them again for this update to take effect.";


if(description)
{
  script_id(881771);
  script_version("$Revision: 8466 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 07:58:30 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-08-01 18:43:34 +0530 (Thu, 01 Aug 2013)");
  script_cve_id("CVE-2013-2231");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for qemu-guest-agent CESA-2013:1100 centos6 ");


  tag_affected = "qemu-guest-agent on CentOS 6";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2013:1100");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-July/019874.html");
  script_tag(name: "summary" , value: "Check for the Version of qemu-guest-agent");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.355.0.1.el6.centos.6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-guest-agent-win32", rpm:"qemu-guest-agent-win32~0.12.1.2~2.355.0.1.el6.centos.6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.355.0.1.el6.centos.6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.355.0.1.el6.centos.6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.355.0.1.el6.centos.6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
