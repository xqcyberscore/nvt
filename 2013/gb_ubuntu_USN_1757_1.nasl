###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1757_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for python-django USN-1757-1
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
tag_insight = "James Kettle discovered that Django did not properly filter the Host HTTP
  header when processing certain requests. An attacker could exploit this to
  generate and display arbitrary URLs to users. Although this issue had been
  previously addressed in USN-1632-1, this update adds additional hardening
  measures to host header validation. This update also adds a new
  ALLOWED_HOSTS setting that can be set to a list of acceptable values for
  headers. (CVE-2012-4520)

  Orange Tsai discovered that Django incorrectly performed permission checks
  when displaying the history view in the admin interface. An administrator
  could use this flaw to view the history of any object, regardless of
  intended permissions. (CVE-2013-0305)

  It was discovered that Django incorrectly handled a large number of forms
  when generating formsets. An attacker could use this flaw to cause Django
  to consume memory, resulting in a denial of service. (CVE-2013-0306)

  It was discovered that Django incorrectly deserialized XML. An attacker
  could use this flaw to perform entity-expansion and external-entity/DTD
  attacks. This updated modified Django behaviour to no longer allow DTDs,
  perform entity expansion, or fetch external entities/DTDs. (CVE-2013-1664,
  CVE-2013-1665)";


tag_affected = "python-django on Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1757-1/");
  script_id(841353);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-03-08 10:23:37 +0530 (Fri, 08 Mar 2013)");
  script_cve_id("CVE-2012-4520", "CVE-2013-0305", "CVE-2013-0306", "CVE-2013-1664",
                "CVE-2013-1665");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_xref(name: "USN", value: "1757-1");
  script_name("Ubuntu Update for python-django USN-1757-1");

  script_summary("Check for the Version of python-django");
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

  if ((res = isdpkgvuln(pkg:"python-django", ver:"1.3.1-4ubuntu1.6", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"python-django", ver:"1.3-2ubuntu1.6", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-django", ver:"1.1.1-2ubuntu1.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"python-django", ver:"1.4.1-2ubuntu0.3", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
