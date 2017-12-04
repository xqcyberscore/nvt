###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2209_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for libvirt USN-2209-1
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
  script_id(841804);
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-05-12 09:12:52 +0530 (Mon, 12 May 2014)");
  script_cve_id("CVE-2013-6456", "CVE-2013-7336");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:N/I:P/A:C");
  script_name("Ubuntu Update for libvirt USN-2209-1");

  tag_insight = "It was discovered that libvirt incorrectly handled symlinks
when using the LXC driver. An attacker could possibly use this issue to delete
host devices, create arbitrary nodes, and shutdown or power off the host.
(CVE-2013-6456)

Marian Krcmarik discovered that libvirt incorrectly handled seamless SPICE
migrations. An attacker could possibly use this issue to cause a denial of
service. (CVE-2013-7336)";

  tag_affected = "libvirt on Ubuntu 13.10";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2209-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2209-1/");
  script_summary("Check for the Version of libvirt");
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

if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"libvirt-bin", ver:"1.1.1-0ubuntu8.11", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libvirt0", ver:"1.1.1-0ubuntu8.11", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
