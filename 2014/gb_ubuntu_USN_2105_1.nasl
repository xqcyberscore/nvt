###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2105_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for maas USN-2105-1
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
  script_id(841711);
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-02-17 11:40:03 +0530 (Mon, 17 Feb 2014)");
  script_cve_id("CVE-2013-1070", "CVE-2013-1069");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Ubuntu Update for maas USN-2105-1");

  tag_insight = "James Troup discovered that MAAS stored RabbitMQ
authentication credentials in a world-readable file. A local authenticated
user could read this password and potentially gain privileges of other
user accounts. This update restricts the file permissions to prevent
unintended access. (CVE-2013-1070)

Chris Glass discovered that the MAAS API was vulnerable to cross-site
scripting vulnerabilities. With cross-site scripting vulnerabilities,
if a user were tricked into viewing a specially crafted page, a remote
attacker could exploit this to modify the contents, or steal confidential
data, within the same domain. (CVE-2013-1069)";

  tag_affected = "maas on Ubuntu 13.10 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2105-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2105-1/");
  script_summary("Check for the Version of maas");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"maas-region-controller", ver:"1.2+bzr1373+dfsg-0ubuntu1~12.04.5", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-django-maas", ver:"1.2+bzr1373+dfsg-0ubuntu1~12.04.5", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"maas-region-controller", ver:"1.4+bzr1693+dfsg-0ubuntu2.3", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-django-maas", ver:"1.4+bzr1693+dfsg-0ubuntu2.3", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"maas-region-controller", ver:"1.2+bzr1373+dfsg-0ubuntu1.2", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-django-maas", ver:"1.2+bzr1373+dfsg-0ubuntu1.2", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
