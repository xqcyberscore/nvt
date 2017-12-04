###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1273_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for pidgin USN-1273-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Marius Wachtler discovered that Pidgin incorrectly handled malformed YMSG
  messages in the Yahoo! protocol handler. A remote attacker could send a
  specially crafted message and cause Pidgin to crash, leading to a denial
  of service. This issue only affected Ubuntu 10.04 LTS and 10.10.
  (CVE-2011-1091)

  Marius Wachtler discovered that Pidgin incorrectly handled HTTP 100
  responses in the MSN protocol handler. A remote attacker could send a
  specially crafted message and cause Pidgin to crash, leading to a denial
  of service. (CVE-2011-3184)

  Diego Bauche Madero discovered that Pidgin incorrectly handled UTF-8
  sequences in the SILC protocol handler. A remote attacker could send a
  specially crafted message and cause Pidgin to crash, leading to a denial
  of service.  (CVE-2011-3594)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1273-1";
tag_affected = "pidgin on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1273-1/");
  script_id(840822);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-11-25 12:03:41 +0530 (Fri, 25 Nov 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_xref(name: "USN", value: "1273-1");
  script_cve_id("CVE-2011-1091", "CVE-2011-3184", "CVE-2011-3594");
  script_name("Ubuntu Update for pidgin USN-1273-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"pidgin", ver:"1:2.7.3-1ubuntu3.3", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"pidgin", ver:"1:2.6.6-1ubuntu4.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"pidgin", ver:"1:2.7.11-1ubuntu2.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
