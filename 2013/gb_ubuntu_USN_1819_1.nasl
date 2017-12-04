###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1819_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for openjdk-6 USN-1819-1
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
tag_insight = "Ben Murphy discovered a vulnerability in the OpenJDK JRE related to
  information disclosure and data integrity. An attacker could exploit this
  to execute arbitrary code. (CVE-2013-0401)

  James Forshaw discovered a vulnerability in the OpenJDK JRE related to
  information disclosure, data integrity and availability. An attacker could
  exploit this to execute arbitrary code. (CVE-2013-1488)

  Several vulnerabilities were discovered in the OpenJDK JRE related to
  information disclosure, data integrity and availability. An attacker could
  exploit these to cause a denial of service or expose sensitive data over
  the network. (CVE-2013-1518, CVE-2013-1537, CVE-2013-1557, CVE-2013-1558,
  CVE-2013-1569, CVE-2013-2383, CVE-2013-2384, CVE-2013-2420, CVE-2013-2421,
  CVE-2013-2422, CVE-2013-2426, CVE-2013-2429, CVE-2013-2430, CVE-2013-2431,
  CVE-2013-2436)

  Two vulnerabilities were discovered in the OpenJDK JRE related to
  confidentiality. An attacker could exploit these to expose sensitive data
  over the network. (CVE-2013-2415, CVE-2013-2424)

  Two vulnerabilities were discovered in the OpenJDK JRE related to
  availability. An attacker could exploit these to cause a denial of service.
  (CVE-2013-2417, CVE-2013-2419)";


tag_affected = "openjdk-6 on Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841421);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-05-09 10:26:30 +0530 (Thu, 09 May 2013)");
  script_cve_id("CVE-2013-0401", "CVE-2013-1488", "CVE-2013-1518", "CVE-2013-1537",
                "CVE-2013-1557", "CVE-2013-1558", "CVE-2013-1569", "CVE-2013-2383",
                "CVE-2013-2384", "CVE-2013-2420", "CVE-2013-2421", "CVE-2013-2422",
                "CVE-2013-2426", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2431",
                "CVE-2013-2436", "CVE-2013-2415", "CVE-2013-2424", "CVE-2013-2417",
                "CVE-2013-2419");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for openjdk-6 USN-1819-1");

  script_xref(name: "USN", value: "1819-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1819-1/");
  script_summary("Check for the Version of openjdk-6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b27-1.12.5-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b27-1.12.5-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b27-1.12.5-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b27-1.12.5-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b27-1.12.5-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b27-1.12.5-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b27-1.12.5-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b27-1.12.5-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b27-1.12.5-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b27-1.12.5-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b27-1.12.5-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b27-1.12.5-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b27-1.12.5-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b27-1.12.5-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b27-1.12.5-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b27-1.12.5-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b27-1.12.5-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
