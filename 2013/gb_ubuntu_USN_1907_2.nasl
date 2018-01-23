###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1907_2.nasl 8483 2018-01-22 06:58:04Z teissa $
#
# Ubuntu Update for icedtea-web USN-1907-2
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

if(description)
{
  script_id(841505);
  script_version("$Revision: 8483 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 07:58:04 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-08-01 19:08:53 +0530 (Thu, 01 Aug 2013)");
  script_cve_id("CVE-2013-1500", "CVE-2013-2454", "CVE-2013-2458", "CVE-2013-1571",
                "CVE-2013-2407", "CVE-2013-2412", "CVE-2013-2443", "CVE-2013-2446",
                "CVE-2013-2447", "CVE-2013-2449", "CVE-2013-2452", "CVE-2013-2456",
                "CVE-2013-2444", "CVE-2013-2445", "CVE-2013-2450", "CVE-2013-2448",
                "CVE-2013-2451", "CVE-2013-2459", "CVE-2013-2460", "CVE-2013-2461",
                "CVE-2013-2463", "CVE-2013-2465", "CVE-2013-2469", "CVE-2013-2470",
                "CVE-2013-2471", "CVE-2013-2472", "CVE-2013-2473", "CVE-2013-2453",
                "CVE-2013-2455", "CVE-2013-2457");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for icedtea-web USN-1907-2");

  tag_insight = "USN-1907-1 fixed vulnerabilities in OpenJDK 7. Due to upstream changes,
IcedTea Web needed an update to work with the new OpenJDK 7.

Original advisory details:

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit these
to expose sensitive data over the network. (CVE-2013-1500, CVE-2013-2454,
CVE-2013-2458)

A vulnerability was discovered in the OpenJDK Javadoc related to data
integrity. (CVE-2013-1571)

A vulnerability was discovered in the OpenJDK JRE related to information
disclosure and availability. An attacker could exploit this to cause a
denial of service or expose sensitive data over the network.
(CVE-2013-2407)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure. An attacker could exploit these to expose sensitive
data over the network. (CVE-2013-2412, CVE-2013-2443, CVE-2013-2446,
CVE-2013-2447, CVE-2013-2449, CVE-2013-2452, CVE-2013-2456)

Several vulnerabilities were discovered in the OpenJDK JRE related to
availability. An attacker could exploit these to cause a denial of service.
(CVE-2013-2444, CVE-2013-2445, CVE-2013-2450)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure, data integrity and availability. An attacker could
exploit these to cause a denial of service or expose sensitive data over
the network. (CVE-2013-2448, CVE-2013-2451, CVE-2013-2459, CVE-2013-2460,
CVE-2013-2461, CVE-2013-2463, CVE-2013-2465, CVE-2013-2469, CVE-2013-2470,
CVE-2013-2471, CVE-2013-2472, CVE-2013-2473)

Several vulnerabilities were discovered in the OpenJDK JRE related to data
integrity. (CVE-2013-2453, CVE-2013-2455, CVE-2013-2457)";

  tag_affected = "icedtea-web on Ubuntu 13.04 ,
Ubuntu 12.10 ,
Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "1907-2");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1907-2/");
  script_tag(name: "summary" , value: "Check for the Version of icedtea-web");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.2.3-0ubuntu0.12.04.3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.3.2-1ubuntu0.12.10.2", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.3.2-1ubuntu1.1", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
