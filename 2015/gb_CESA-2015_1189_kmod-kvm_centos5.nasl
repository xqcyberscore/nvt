###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kmod-kvm CESA-2015:1189 centos5 
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
  script_oid("1.3.6.1.4.1.25623.1.0.882211");
  script_version("$Revision: 6657 $");
  script_cve_id("CVE-2015-3209");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:50:44 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-07-03 11:19:11 +0530 (Fri, 03 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kmod-kvm CESA-2015:1189 centos5 ");
  script_tag(name: "summary", value: "Check the version of kmod-kvm");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "KVM (Kernel-based Virtual Machine) is a full
  virtualization solution for Linux on AMD64 and Intel 64 systems.

A flaw was found in the way QEMU's AMD PCnet Ethernet emulation handled
multi-TMD packets with a length above 4096 bytes. A privileged guest user
in a guest with an AMD PCNet ethernet card enabled could potentially use
this flaw to execute arbitrary code on the host with the privileges of the
hosting QEMU process. (CVE-2015-3209)

Red Hat would like to thank Matt Tait of Google's Project Zero security
team for reporting this issue.

All kvm users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. Note: The procedure in
the Solution section must be performed before this update will take effect.
");
  script_tag(name: "affected", value: "kmod-kvm on CentOS 5");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "CESA", value: "2015:1189");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2015-June/021224.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~273.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kmod-kvm-debug", rpm:"kmod-kvm-debug~83~273.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~273.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~273.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~273.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
