###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2306_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for eglibc USN-2306-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841918");
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-08-05 16:50:59 +0530 (Tue, 05 Aug 2014)");
  script_cve_id("CVE-2013-4357", "CVE-2013-4458", "CVE-2014-0475", "CVE-2014-4043");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for eglibc USN-2306-1");

  tag_insight = "Maksymilian Arciemowicz discovered that the GNU C Library
incorrectly handled the getaddrinfo() function. An attacker could use this
issue to cause a denial of service. This issue only affected Ubuntu 10.04 LTS.
(CVE-2013-4357)

It was discovered that the GNU C Library incorrectly handled the
getaddrinfo() function. An attacker could use this issue to cause a denial
of service. This issue only affected Ubuntu 10.04 LTS and Ubuntu 12.04 LTS.
(CVE-2013-4458)

Stephane Chazelas discovered that the GNU C Library incorrectly handled
locale environment variables. An attacker could use this issue to possibly
bypass certain restrictions such as the ForceCommand restrictions in
OpenSSH. (CVE-2014-0475)

David Reid, Glyph Lefkowitz, and Alex Gaynor discovered that the GNU C
Library incorrectly handled posix_spawn_file_actions_addopen() path
arguments. An attacker could use this issue to cause a denial of service.
(CVE-2014-4043)";

  tag_affected = "eglibc on Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS ,
  Ubuntu 10.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2306-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2306-1/");
  script_summary("Check for the Version of eglibc");
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

  if ((res = isdpkgvuln(pkg:"libc6:i386", ver:"2.19-0ubuntu6.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libc6", ver:"2.15-0ubuntu10.6", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libc6", ver:"2.11.1-0ubuntu7.14", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
