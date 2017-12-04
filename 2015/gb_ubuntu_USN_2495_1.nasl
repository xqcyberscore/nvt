###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for oxide-qt USN-2495-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842090");
  script_version("$Revision: 7956 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 06:53:44 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-02-11 05:39:51 +0100 (Wed, 11 Feb 2015)");
  script_cve_id("CVE-2015-1209", "CVE-2015-1210", "CVE-2015-1211", "CVE-2015-1212");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for oxide-qt USN-2495-1");
  script_tag(name: "summary", value: "Check the version of oxide-qt");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "A use-after-free bug was discovered in the
DOM implementation in Blink. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a denial of
service via renderer crash or execute arbitrary code with the privileges of the
sandboxed render process. (CVE-2015-1209)

It was discovered that V8 did not properly consider frame access
restrictions when throwing exceptions in some circumstances. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit this to bypass same origin restrictions.
(CVE-2015-1210)

It was discovered that Chromium did not properly restrict the URI scheme
during ServiceWorker registration. If a user were tricked in to
downloading and opening a specially crafted HTML file, an attacker could
potentially exploit this to bypass security restrictions. (CVE-2015-1211)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1212)");
  script_tag(name: "affected", value: "oxide-qt on Ubuntu 14.10 ,
  Ubuntu 14.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "USN", value: "2495-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2495-1/");
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

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:amd64", ver:"1.4.3-0ubuntu0.14.10.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:i386", ver:"1.4.3-0ubuntu0.14.10.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"oxideqt-codecs:amd64", ver:"1.4.3-0ubuntu0.14.10.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"oxideqt-codecs:i386", ver:"1.4.3-0ubuntu0.14.10.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }


  if ((res = isdpkgvuln(pkg:"oxideqt-codecs-extra:amd64", ver:"1.4.3-0ubuntu0.14.10.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"oxideqt-codecs-extra:i386", ver:"1.4.3-0ubuntu0.14.10.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }


  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:amd64", ver:"1.4.3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:i386", ver:"1.4.3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"oxideqt-codecs:amd64", ver:"1.4.3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"oxideqt-codecs:i386", ver:"1.4.3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL) 
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"oxideqt-codecs-extra:amd64", ver:"1.4.3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"oxideqt-codecs-extra:i386", ver:"1.4.3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
