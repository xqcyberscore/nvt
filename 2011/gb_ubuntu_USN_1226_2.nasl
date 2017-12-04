###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1226_2.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for cifs-utils USN-1226-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Dan Rosenberg discovered that cifs-utils incorrectly handled changes to the
  mtab file. A local attacker could use this issue to corrupt the mtab file,
  possibly leading to a denial of service. (CVE-2011-1678)

  Jan Lieskovsky discovered that cifs-utils incorrectly filtered certain
  strings being added to the mtab file. A local attacker could use this issue
  to corrupt the mtab file, possibly leading to a denial of service.
  (CVE-2011-2724)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1226-2";
tag_affected = "cifs-utils on Ubuntu 11.04 ,
  Ubuntu 10.10";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1226-2/");
  script_id(840765);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-10-10 16:05:48 +0200 (Mon, 10 Oct 2011)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_xref(name: "USN", value: "1226-2");
  script_cve_id("CVE-2011-1678", "CVE-2011-2724");
  script_name("Ubuntu Update for cifs-utils USN-1226-2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"smbfs", ver:"2:4.5-2ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"smbfs", ver:"2:4.5-2ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
