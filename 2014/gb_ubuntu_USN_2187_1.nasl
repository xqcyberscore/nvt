###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2187_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for openjdk-7 USN-2187-1
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

include("revisions-lib.inc");

if(description)
{
  script_id(841791);
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-05-05 11:23:19 +0530 (Mon, 05 May 2014)");
  script_cve_id("CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0452",
                "CVE-2014-0454", "CVE-2014-0455", "CVE-2014-0456", "CVE-2014-0457",
                "CVE-2014-0458", "CVE-2014-0461", "CVE-2014-2397", "CVE-2014-2402",
                "CVE-2014-2412", "CVE-2014-2414", "CVE-2014-2421", "CVE-2014-2423",
                "CVE-2014-2427", "CVE-2014-0453", "CVE-2014-0460", "CVE-2014-0459",
                "CVE-2014-1876", "CVE-2014-2398", "CVE-2014-2413", "CVE-2014-2403");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for openjdk-7 USN-2187-1");

  tag_insight = "Several vulnerabilities were discovered in the OpenJDK JRE
related to information disclosure, data integrity and availability. An attacker
could exploit these to cause a denial of service or expose sensitive data over
the network. (CVE-2014-0429, CVE-2014-0446, CVE-2014-0451, CVE-2014-0452,
CVE-2014-0454, CVE-2014-0455, CVE-2014-0456, CVE-2014-0457, CVE-2014-0458,
CVE-2014-0461, CVE-2014-2397, CVE-2014-2402, CVE-2014-2412, CVE-2014-2414,
CVE-2014-2421, CVE-2014-2423, CVE-2014-2427)

Two vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit these
to expose sensitive data over the network. (CVE-2014-0453, CVE-2014-0460)

A vulnerability was discovered in the OpenJDK JRE related to availability.
An attacker could exploit this to cause a denial of service.
(CVE-2014-0459)

Jakub Wilk discovered that the OpenJDK JRE incorrectly handled temporary
files. A local attacker could possibly use this issue to overwrite
arbitrary files. In the default installation of Ubuntu, this should be
prevented by the Yama link restrictions. (CVE-2014-1876)

Two vulnerabilities were discovered in the OpenJDK JRE related to data
integrity. (CVE-2014-2398, CVE-2014-2413)

A vulnerability was discovered in the OpenJDK JRE related to information
disclosure. An attacker could exploit this to expose sensitive data over
the network. (CVE-2014-2403)";

  tag_affected = "openjdk-7 on Ubuntu 14.04 LTS ,
  Ubuntu 13.10 ,
  Ubuntu 12.10";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2187-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2187-1/");
  script_summary("Check for the Version of openjdk-7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm:i386", ver:"7u55-2.4.7-1ubuntu1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre:i386", ver:"7u55-2.4.7-1ubuntu1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-headless:i386", ver:"7u55-2.4.7-1ubuntu1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u55-2.4.7-1ubuntu1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-zero:i386", ver:"7u55-2.4.7-1ubuntu1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm:i386", ver:"7u55-2.4.7-1ubuntu1~0.13.10.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre:i386", ver:"7u55-2.4.7-1ubuntu1~0.13.10.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-headless:i386", ver:"7u55-2.4.7-1ubuntu1~0.13.10.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u55-2.4.7-1ubuntu1~0.13.10.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-zero:i386", ver:"7u55-2.4.7-1ubuntu1~0.13.10.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"icedtea-7-jre-cacao", ver:"7u55-2.4.7-1ubuntu1~0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u55-2.4.7-1ubuntu1~0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u55-2.4.7-1ubuntu1~0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u55-2.4.7-1ubuntu1~0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u55-2.4.7-1ubuntu1~0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u55-2.4.7-1ubuntu1~0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
