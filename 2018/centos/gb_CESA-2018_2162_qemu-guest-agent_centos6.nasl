###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_2162_qemu-guest-agent_centos6.nasl 10547 2018-07-20 07:18:47Z ckuersteiner $
#
# CentOS Update for qemu-guest-agent CESA-2018:2162 centos6 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882923");
  script_version("$Revision: 10547 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-20 09:18:47 +0200 (Fri, 20 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-14 05:51:56 +0200 (Sat, 14 Jul 2018)");
  script_cve_id("CVE-2017-13672", "CVE-2018-3639", "CVE-2018-5683", "CVE-2018-7858");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for qemu-guest-agent CESA-2018:2162 centos6 ");
  script_tag(name:"summary", value:"Check the version of qemu-guest-agent");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Kernel-based Virtual Machine (KVM) is a full
  virtualization solution for Linux on a variety of architectures. The qemu-kvm
  packages provide the user-space component for running virtual machines that use
  KVM.

Security Fix(es):

* An industry-wide issue was found in the way many modern microprocessor
designs have implemented speculative execution of Load &amp  Store instructions
(a commonly used performance optimization). It relies on the presence of a
precisely-defined instruction sequence in the privileged code as well as
the fact that memory read from address to which a recent memory write has
occurred may see an older value and subsequently cause an update into the
microprocessor's data cache even for speculatively executed instructions
that never actually commit (retire). As a result, an unprivileged attacker
could use this flaw to read privileged memory by conducting targeted cache
side-channel attacks. (CVE-2018-3639)

Note: This is the qemu-kvm side of the CVE-2018-3639 mitigation.

* QEMU: cirrus: OOB access when updating VGA display (CVE-2018-7858)

* QEMU: vga: OOB read access during display update (CVE-2017-13672)

* Qemu: Out-of-bounds read in vga_draw_text routine (CVE-2018-5683)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank Ken Johnson (Microsoft Security Response
Center) and Jann Horn (Google Project Zero) for reporting CVE-2018-3639 
Ross Lagerwall (Citrix.com) for reporting CVE-2018-7858  David Buchanan for
reporting CVE-2017-13672  and Jiang Xin and Lin ZheCheng for reporting
CVE-2018-5683.
");
  script_tag(name:"affected", value:"qemu-guest-agent on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2018:2162");
  script_xref(name:"URL" , value:"http://lists.centos.org/pipermail/centos-announce/2018-July/022967.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.506.el6_10.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.506.el6_10.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.506.el6_10.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.506.el6_10.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
