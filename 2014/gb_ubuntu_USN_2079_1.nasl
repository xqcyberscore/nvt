###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2079_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for openssl USN-2079-1
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
  script_id(841683);
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-01-10 12:00:29 +0530 (Fri, 10 Jan 2014)");
  script_cve_id("CVE-2013-4353", "CVE-2013-6449", "CVE-2013-6450");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Ubuntu Update for openssl USN-2079-1");

  tag_insight = "Anton Johansson discovered that OpenSSL incorrectly handled certain invalid
TLS handshakes. A remote attacker could use this issue to cause OpenSSL to
crash, resulting in a denial of service. (CVE-2013-4353)

Ron Barber discovered that OpenSSL used an incorrect data structure to
obtain a version number. A remote attacker could use this issue to cause
OpenSSL to crash, resulting in a denial of service. (CVE-2013-6449)

Dmitry Sobinov discovered that OpenSSL incorrectly handled certain DTLS
retransmissions. A remote attacker could use this issue to cause OpenSSL to
crash, resulting in a denial of service. (CVE-2013-6450)

This update also disables the default use of the RdRand feature of certain
Intel CPUs as the sole source of entropy.";

  tag_affected = "openssl on Ubuntu 13.10 ,
  Ubuntu 13.04 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2079-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2079-1/");
  script_summary("Check for the Version of openssl");
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

if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1c-3ubuntu2.6", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1-4ubuntu5.11", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1e-3ubuntu1.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1c-4ubuntu8.2", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
