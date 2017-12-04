###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1318_1.nasl 7960 2017-12-01 06:58:16Z santu $
#
# Ubuntu Update for linux-fsl-imx51 USN-1318-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Peter Huewe discovered an information leak in the handling of reading
  security-related TPM data. A local, unprivileged user could read the
  results of a previous TPM command. (CVE-2011-1162)

  Clement Lecigne discovered a bug in the HFS filesystem. A local attacker
  could exploit this to cause a kernel oops. (CVE-2011-2203)

  A flaw was found in how the Linux kernel handles user-defined key types. An
  unprivileged local user could exploit this to crash the system.
  (CVE-2011-4110)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1318-1";
tag_affected = "linux-fsl-imx51 on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1318-1/");
  script_id(840854);
  script_version("$Revision: 7960 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:58:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-01-09 13:29:37 +0530 (Mon, 09 Jan 2012)");
  script_xref(name: "USN", value: "1318-1");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2011-1162", "CVE-2011-2203", "CVE-2011-4110");
  script_name("Ubuntu Update for linux-fsl-imx51 USN-1318-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.31-612-imx51", ver:"2.6.31-612.32", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
