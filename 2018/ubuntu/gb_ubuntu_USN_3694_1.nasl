###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3694_1.nasl 10374 2018-07-02 04:44:41Z asteins $
#
# Ubuntu Update for nasm USN-3694-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843571");
  script_version("$Revision: 10374 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-02 06:44:41 +0200 (Mon, 02 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-06-29 05:46:02 +0200 (Fri, 29 Jun 2018)");
  script_cve_id("CVE-2017-10686", "CVE-2017-11111", "CVE-2017-14228", "CVE-2017-17810", "CVE-2017-17811", "CVE-2017-17812", "CVE-2017-17813", "CVE-2017-17814", "CVE-2017-17815", "CVE-2017-17816", "CVE-2017-17817", "CVE-2017-17818", "CVE-2017-17819", "CVE-2017-17820", "CVE-2018-8881");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for nasm USN-3694-1");
  script_tag(name:"summary", value:"Check the version of nasm");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that NASM incorrectly handled certain source files. If a
user or automated system were tricked into processing a specially crafted
source file, a remote attacker could use these issues to cause NASM to
crash, resulting in a denial of service, or possibly execute arbitrary
code.");
  script_tag(name:"affected", value:"nasm on Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"USN", value:"3694-1");
  script_xref(name:"URL" , value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2018-June/004462.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"nasm", ver:"2.10.09-1ubuntu0.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}