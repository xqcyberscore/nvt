###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2232_3.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for openssl USN-2232-3
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
  script_oid("1.3.6.1.4.1.25623.1.0.841867");
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-07-01 21:24:39 +0530 (Tue, 01 Jul 2014)");
  script_cve_id("CVE-2014-0224", "CVE-2014-0195", "CVE-2014-0221", "CVE-2014-3470");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for openssl USN-2232-3");

  tag_insight = "USN-2232-1 fixed vulnerabilities in OpenSSL. The upstream fix
for CVE-2014-0224 caused a regression for certain applications that use
renegotiation, such as PostgreSQL. This update fixes the problem.

Original advisory details:

J&#252 ri Aedla discovered that OpenSSL incorrectly handled invalid DTLS
fragments. A remote attacker could use this issue to cause OpenSSL to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 12.04 LTS, Ubuntu 13.10, and
Ubuntu 14.04 LTS. (CVE-2014-0195)
Imre Rad discovered that OpenSSL incorrectly handled DTLS recursions. A
remote attacker could use this issue to cause OpenSSL to crash, resulting
in a denial of service. (CVE-2014-0221)
KIKUCHI Masashi discovered that OpenSSL incorrectly handled certain
handshakes. A remote attacker could use this flaw to perform a
man-in-the-middle attack and possibly decrypt and modify traffic.
(CVE-2014-0224)
Felix Gr&#246 bert and Ivan Fratri&#263  discovered that OpenSSL incorrectly handled
anonymous ECDH ciphersuites. A remote attacker could use this issue to
cause OpenSSL to crash, resulting in a denial of service. This issue only
affected Ubuntu 12.04 LTS, Ubuntu 13.10, and Ubuntu 14.04 LTS.
(CVE-2014-3470)";

  tag_affected = "openssl on Ubuntu 14.04 LTS ,
  Ubuntu 13.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 10.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2232-3");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2232-3/");
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

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:i386", ver:"1.0.1f-1ubuntu2.4", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1-4ubuntu5.16", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8k-7ubuntu8.19", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:i386", ver:"1.0.1e-3ubuntu1.6", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
