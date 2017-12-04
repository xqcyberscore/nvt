###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2347_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for python-django USN-2347-1
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841970");
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-09-17 05:58:45 +0200 (Wed, 17 Sep 2014)");
  script_cve_id("CVE-2014-0480", "CVE-2014-0481", "CVE-2014-0482", "CVE-2014-0483");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("Ubuntu Update for python-django USN-2347-1");
  script_tag(name: "insight", value: "Florian Apolloner discovered that Django
incorrectly validated URLs. A remote attacker could use this issue to conduct
phishing attacks. (CVE-2014-0480)

David Wilson discovered that Django incorrectly handled file name
generation. A remote attacker could use this issue to cause Django to
consume resources, resulting in a denial of service. (CVE-2014-0481)

David Greisen discovered that Django incorrectly handled certain headers in
contrib.auth.middleware.RemoteUserMiddleware. A remote authenticated user
could use this issue to hijack web sessions. (CVE-2014-0482)

Collin Anderson discovered that Django incorrectly checked if a field
represented a relationship between models in the administrative interface.
A remote authenticated user could use this issue to possibly obtain
sensitive information. (CVE-2014-0483)");
  script_tag(name: "affected", value: "python-django on Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS ,
  Ubuntu 10.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name: "USN", value: "2347-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2347-1/");
  script_summary("Check for the Version of python-django");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"python-django", ver:"1.6.1-2ubuntu0.4", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-django", ver:"1.3.1-4ubuntu1.12", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-django", ver:"1.1.1-2ubuntu1.13", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
