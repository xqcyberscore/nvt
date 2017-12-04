###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1641_1.nasl 7960 2017-12-01 06:58:16Z santu $
#
# Ubuntu Update for keystone USN-1641-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Vijaya Erukala discovered that Keystone did not properly invalidate
  EC2-style credentials such that if credentials were removed from a tenant,
  an authenticated and authorized user using those credentials may still be
  allowed access beyond the account owner's expectations. (CVE-2012-5571)

  It was discovered that Keystone did not properly implement token
  expiration. A remote attacker could use this to continue to access an
  account that is disabled or has a changed password. This issue was
  previously fixed as CVE-2012-3426 but was reintroduced in Ubuntu 12.10.
  (CVE-2012-5563)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1641-1";
tag_affected = "keystone on Ubuntu 12.10 ,
  Ubuntu 12.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1641-1/");
  script_id(841227);
  script_version("$Revision: 7960 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:58:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-11-29 09:40:15 +0530 (Thu, 29 Nov 2012)");
  script_cve_id("CVE-2012-5571", "CVE-2012-3426", "CVE-2012-5563");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_xref(name: "USN", value: "1641-1");
  script_name("Ubuntu Update for keystone USN-1641-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  script_tag(name : "summary" , value : tag_summary);
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

  if ((res = isdpkgvuln(pkg:"python-keystone", ver:"2012.1+stable~20120824-a16a0ab9-0ubuntu2.3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"python-keystone", ver:"2012.2-0ubuntu1.2", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
