###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for dracut FEDORA-2016-94d1c64fe2
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
  script_oid("1.3.6.1.4.1.25623.1.0.810128");
  script_version("$Revision: 11884 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:33:40 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-02 14:04:56 +0100 (Fri, 02 Dec 2016)");
  script_cve_id("CVE-2016-8637");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for dracut FEDORA-2016-94d1c64fe2");
  script_tag(name: "summary", value: "Check the version of dracut");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "dracut contains tools to create a bootable
  initramfs for 2.6 Linux kernels. Unlike existing implementations, dracut does
  hard-code as little as possible into the initramfs. dracut contains various
  modules which are driven by the event-based udev. Having root on MD, DM, LVM2,
  LUKS is supported as well as NFS, iSCSI, NBD, FCoE with the dracut-network
  package.");

  script_tag(name: "affected", value: "dracut on Fedora 24");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2016-94d1c64fe2");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2VA7LTNATN2EKBHSSHB35W5AXITXVLG6");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC24")
{

  if ((res = isrpmvuln(pkg:"dracut", rpm:"dracut~044~21.fc24", rls:"FC24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
