###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for openjdk-7 USN-2487-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842078");
  script_version("$Revision: 7956 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 06:53:44 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-01-28 06:11:16 +0100 (Wed, 28 Jan 2015)");
  script_cve_id("CVE-2014-3566", "CVE-2014-6587", "CVE-2014-6601", "CVE-2015-0395",
                "CVE-2015-0408", "CVE-2015-0412", "CVE-2014-6585", "CVE-2014-6591",
                "CVE-2015-0400", "CVE-2015-0407", "CVE-2014-6593", "CVE-2015-0383",
                "CVE-2015-0410", "CVE-2015-0413");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for openjdk-7 USN-2487-1");
  script_tag(name: "summary", value: "Check the version of openjdk-7");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Several vulnerabilities were discovered in
the OpenJDK JRE related to information disclosure, data integrity and availability.
An attacker could exploit these to cause a denial of service or expose sensitive
data over the network. (CVE-2014-3566, CVE-2014-6587, CVE-2014-6601, CVE-2015-0395,
CVE-2015-0408, CVE-2015-0412)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure. An attacker could exploit these to expose sensitive
data over the network. (CVE-2014-6585, CVE-2014-6591, CVE-2015-0400,
CVE-2015-0407)

A vulnerability was discovered in the OpenJDK JRE related to
information disclosure and integrity. An attacker could exploit this to
expose sensitive data over the network. (CVE-2014-6593)

A vulnerability was discovered in the OpenJDK JRE related to integrity and
availability. An attacker could exploit this to cause a denial of service.
(CVE-2015-0383)

A vulnerability was discovered in the OpenJDK JRE related to availability.
An attacker could this exploit to cause a denial of service.
(CVE-2015-0410)

A vulnerability was discovered in the OpenJDK JRE related to data
integrity. (CVE-2015-0413)");
  script_tag(name: "affected", value: "openjdk-7 on Ubuntu 14.10 ,
  Ubuntu 14.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "USN", value: "2487-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2487-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(release == "UBUNTU14.10")
{

  if ((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm:amd64", ver:"7u75-2.5.4-1~utopic1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm:i386", ver:"7u75-2.5.4-1~utopic1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre:amd64", ver:"7u75-2.5.4-1~utopic1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre:i386", ver:"7u75-2.5.4-1~utopic1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-headless:amd64", ver:"7u75-2.5.4-1~utopic1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-headless:i386", ver:"7u75-2.5.4-1~utopic1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u75-2.5.4-1~utopic1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-zero:amd64", ver:"7u75-2.5.4-1~utopic1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-zero:i386", ver:"7u75-2.5.4-1~utopic1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-source", ver:"7u75-2.5.4-1~utopic1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm:amd64", ver:"7u75-2.5.4-1~trusty1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm:i386", ver:"7u75-2.5.4-1~trusty1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre:amd64", ver:"7u75-2.5.4-1~trusty1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre:i386", ver:"7u75-2.5.4-1~trusty1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-headless:i386", ver:"7u75-2.5.4-1~trusty1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-headless:amd64", ver:"7u75-2.5.4-1~trusty1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u75-2.5.4-1~trusty1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-zero:amd64", ver:"7u75-2.5.4-1~trusty1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-zero:i386", ver:"7u75-2.5.4-1~trusty1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-source", ver:"7u75-2.5.4-1~trusty1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
