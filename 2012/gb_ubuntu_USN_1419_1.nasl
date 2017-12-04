###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1419_1.nasl 7960 2017-12-01 06:58:16Z santu $
#
# Ubuntu Update for puppet USN-1419-1
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
tag_insight = "It was discovered that Puppet used a predictable filename when downloading Mac
  OS X package files. A local attacker could exploit this to overwrite arbitrary
  files. (CVE-2012-1906)

  It was discovered that Puppet incorrectly handled filebucket retrieval
  requests. A local attacker could exploit this to read arbitrary files.
  (CVE-2012-1986)

  It was discovered that Puppet incorrectly handled filebucket store requests. A
  local attacker could exploit this to perform a denial of service via resource
  exhaustion. (CVE-2012-1987)

  It was discovered that Puppet incorrectly handled filebucket requests. A local
  attacker could exploit this to execute arbitrary code via a crafted file path.
  (CVE-2012-1988)

  It was discovered that Puppet used a predictable filename for the Telnet
  connection log file. A local attacker could exploit this to overwrite arbitrary
  files. This issue only affected Ubuntu 11.10. (CVE-2012-1989)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1419-1";
tag_affected = "puppet on Ubuntu 11.10 ,
  Ubuntu 11.04 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1419-1/");
  script_id(840981);
  script_tag(name:"cvss_base", value:"6.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
 script_version("$Revision: 7960 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:58:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-04-13 10:33:28 +0530 (Fri, 13 Apr 2012)");
  script_cve_id("CVE-2012-1906", "CVE-2012-1986", "CVE-2012-1987", "CVE-2012-1988",
                "CVE-2012-1989");
  script_xref(name: "USN", value: "1419-1");
  script_name("Ubuntu Update for puppet USN-1419-1");

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

  if ((res = isdpkgvuln(pkg:"puppet-common", ver:"0.25.4-2ubuntu6.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"puppet-common", ver:"2.7.1-1ubuntu3.6", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"puppet-common", ver:"2.6.4-2ubuntu2.9", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
