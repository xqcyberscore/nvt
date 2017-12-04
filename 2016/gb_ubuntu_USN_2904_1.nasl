###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for thunderbird USN-2904-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842682");
  script_version("$Revision: 7955 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 06:40:43 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-03-10 06:17:04 +0100 (Thu, 10 Mar 2016)");
  script_cve_id("CVE-2015-7575", "CVE-2016-1523", "CVE-2016-1930", "CVE-2016-1935");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for thunderbird USN-2904-1");
  script_tag(name: "summary", value: "Check the version of thunderbird");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Karthikeyan Bhargavan and Gaetan Leurent
  discovered that NSS incorrectly allowed MD5 to be used for TLS 1.2 connections.
  If a remote attacker were able to perform a man-in-the-middle attack, this
  flaw could be exploited to view sensitive information. (CVE-2015-7575)

  Yves Younan discovered that graphite2 incorrectly handled certain malformed
  fonts. If a user were tricked into opening a specially crafted website in a
  browsing context, an attacker could potentially exploit this to cause a
  denial of service via application crash, or execute arbitrary code with the
  privileges of the user invoking Thunderbird. (CVE-2016-1523)

  Bob Clary, Christian Holler, Nils Ohlmeier, Gary Kwong, Jesse Ruderman,
  Carsten Book, and Randell Jesup discovered multiple memory safety issues
  in Thunderbird. If a user were tricked in to opening a specially crafted
  website in a browsing context, an attacker could potentially exploit these
  to cause a denial of service via application crash, or execute arbitrary
  code with the privileges of the user invoking Thunderbird. (CVE-2016-1930)

  Aki Helin discovered a buffer overflow when rendering WebGL content in
  some circumstances. If a user were tricked in to opening a specially
  crafted website in a browsing context, an attacker could potentially
  exploit this to cause a denial of service via application crash, or
  execute arbitrary code with the privileges of the user invoking
  Thunderbird. (CVE-2016-1935)");
  script_tag(name: "affected", value: "thunderbird on Ubuntu 15.10 ,
  Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "USN", value: "2904-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2904-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:38.6.0+build1-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:38.6.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:38.6.0+build1-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
