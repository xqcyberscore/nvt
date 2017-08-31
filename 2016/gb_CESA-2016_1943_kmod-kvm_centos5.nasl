###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kmod-kvm CESA-2016:1943 centos5 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882562");
  script_version("$Revision: 6658 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:51:48 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-09-29 05:43:13 +0200 (Thu, 29 Sep 2016)");
  script_cve_id("CVE-2016-3710", "CVE-2016-5403");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kmod-kvm CESA-2016:1943 centos5 ");
  script_tag(name: "summary", value: "Check the version of kmod-kvm");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "KVM (for Kernel-based Virtual Machine) is a 
full virtualization solution for Linux on x86 hardware. Using KVM, one can run 
multiple virtual machines running unmodified Linux or Windows images. Each 
virtual machine has private virtualized hardware: a network card, disk, 
graphics adapter, etc.

Security Fix(es):

* An out-of-bounds read/write access flaw was found in the way QEMU's VGA
emulation with VESA BIOS Extensions (VBE) support performed read/write
operations using I/O port methods. A privileged guest user could use this
flaw to execute arbitrary code on the host with the privileges of the
host's QEMU process. (CVE-2016-3710)

* Quick Emulator(QEMU) built with the virtio framework is vulnerable to an
unbounded memory allocation issue. It was found that a malicious guest user
could submit more requests than the virtqueue size permits. Processing a
request allocates a VirtQueueElement results in unbounded memory allocation
on the host controlled by the guest. (CVE-2016-5403)

Red Hat would like to thank Wei Xiao (360 Marvel Team) and Qinghao Tang
(360 Marvel Team) for reporting CVE-2016-3710 and hongzhenhao (Marvel Team)
for reporting CVE-2016-5403.

4. Solution:

For details on how to apply this update, which includes the changes
described in this advisory, refer to:

'https://access.redhat.com/articles/11258'
");
  script_tag(name: "affected", value: "kmod-kvm on CentOS 5");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "CESA", value: "2016:1943");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2016-September/022091.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~276.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kmod-kvm-debug", rpm:"kmod-kvm-debug~83~276.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~276.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~276.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~276.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
