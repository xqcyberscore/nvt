###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for webkitgtk USN-2937-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842701");
  script_version("$Revision: 7955 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 06:40:43 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-03-22 06:13:01 +0100 (Tue, 22 Mar 2016)");
  script_cve_id("CVE-2014-1748", "CVE-2015-1071", "CVE-2015-1076", "CVE-2015-1081",
		"CVE-2015-1083", "CVE-2015-1120", "CVE-2015-1122", "CVE-2015-1127",
		"CVE-2015-1153", "CVE-2015-1155", "CVE-2015-3658", "CVE-2015-3659",
		"CVE-2015-3727", "CVE-2015-3731", "CVE-2015-3741", "CVE-2015-3743",
		"CVE-2015-3745", "CVE-2015-3747", "CVE-2015-3748", "CVE-2015-3749",
		"CVE-2015-3752", "CVE-2015-5788", "CVE-2015-5794", "CVE-2015-5801",
		"CVE-2015-5809", "CVE-2015-5822", "CVE-2015-5928");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for webkitgtk USN-2937-1");
  script_tag(name: "summary", value: "Check the version of webkitgtk");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "A large number of security issues were
  discovered in the WebKitGTK+ Web and JavaScript engines. If a user were tricked
  into viewing a malicious website, a remote attacker could exploit a variety of
  issues related to web browser security, including cross-site scripting attacks,
  denial of service attacks, and arbitrary code execution.");
  script_tag(name: "affected", value: "webkitgtk on Ubuntu 15.10 ,
  Ubuntu 14.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "USN", value: "2937-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2937-1/");
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

  if ((res = isdpkgvuln(pkg:"libjavascriptcoregtk-1.0-0:i386", ver:"2.4.10-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libjavascriptcoregtk-1.0-0:amd64", ver:"2.4.10-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libjavascriptcoregtk-3.0-0:i386", ver:"2.4.10-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libjavascriptcoregtk-3.0-0:amd64", ver:"2.4.10-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkitgtk-1.0-0:i386", ver:"2.4.10-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkitgtk-1.0-0:amd64", ver:"2.4.10-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkitgtk-3.0-0:i386", ver:"2.4.10-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkitgtk-3.0-0:amd64", ver:"2.4.10-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"libjavascriptcoregtk-1.0-0:i386", ver:"2.4.10-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libjavascriptcoregtk-1.0-0:amd64", ver:"2.4.10-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libjavascriptcoregtk-3.0-0:i386", ver:"2.4.10-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libjavascriptcoregtk-3.0-0:amd64", ver:"2.4.10-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkitgtk-1.0-0:i386", ver:"2.4.10-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkitgtk-1.0-0:amd64", ver:"2.4.10-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkitgtk-3.0-0:i386", ver:"2.4.10-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkitgtk-3.0-0:amd64", ver:"2.4.10-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}