###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1732_1.nasl 8650 2018-02-03 12:16:59Z teissa $
#
# Ubuntu Update for openssl USN-1732-1
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
tag_insight = "Adam Langley and Wolfgang Ettlingers discovered that OpenSSL incorrectly
  handled certain crafted CBC data when used with AES-NI. A remote attacker
  could use this issue to cause OpenSSL to crash, resulting in a denial of
  service. This issue only affected Ubuntu 12.04 LTS and Ubuntu 12.10.
  (CVE-2012-2686)

  Stephen Henson discovered that OpenSSL incorrectly performed signature
  verification for OCSP responses. A remote attacker could use this issue to
  cause OpenSSL to crash, resulting in a denial of service. (CVE-2013-0166)
  
  Nadhem Alfardan and Kenny Paterson discovered that the TLS protocol as used
  in OpenSSL was vulnerable to a timing side-channel attack known as the
  &quot;Lucky Thirteen&quot; issue. A remote attacker could use this issue to perform
  plaintext-recovery attacks via analysis of timing data. (CVE-2013-0169)";


tag_affected = "openssl on Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 10.04 LTS ,
  Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1732-1/");
  script_id(841327);
  script_version("$Revision: 8650 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:59 +0100 (Sat, 03 Feb 2018) $");
  script_tag(name:"creation_date", value:"2013-02-22 10:12:42 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2012-2686", "CVE-2013-0166", "CVE-2013-0169");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "USN", value: "1732-1");
  script_name("Ubuntu Update for openssl USN-1732-1");

  script_tag(name: "summary" , value: "Check for the Version of openssl");
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

  if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1-4ubuntu5.6", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.0e-2ubuntu4.7", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8k-7ubuntu8.14", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8g-4ubuntu3.20", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1c-3ubuntu2.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
