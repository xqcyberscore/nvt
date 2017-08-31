###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for arm-none-eabi-binutils-cs FEDORA-2014-14874
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.868565");
  script_version("$Revision: 6724 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-14 11:57:17 +0200 (Fri, 14 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-12-08 06:22:34 +0100 (Mon, 08 Dec 2014)");
  script_cve_id("CVE-2014-8501", "CVE-2014-8502", "CVE-2014-8503", "CVE-2014-8504",
                "CVE-2014-8738", "CVE-2014-8737", "CVE-2014-8485");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Update for arm-none-eabi-binutils-cs FEDORA-2014-14874");
  script_tag(name: "summary", value: "Check the version of arm-none-eabi-binutils-cs");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "This is a cross-compilation version of GNU Binutils, which can be used to
assemble and link binaries for the arm-none-eabi platform.

This Binutils package is based on the CodeSourcery
2014.05-28 release, which includes improved ARM target
support compared to the corresponding FSF release.  CodeSourcery
contributes their changes to the FSF, but it takes a while for them to
get merged.  For the ARM target, effectively CodeSourcery is upstream
of FSF.
");
  script_tag(name: "affected", value: "arm-none-eabi-binutils-cs on Fedora 19");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "FEDORA", value: "2014-14874");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145746.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(release == "FC19")
{

  if ((res = isrpmvuln(pkg:"arm-none-eabi-binutils-cs", rpm:"arm-none-eabi-binutils-cs~2014.05.28~3.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
