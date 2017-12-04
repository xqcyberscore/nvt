###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1759_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for puppet USN-1759-1
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
tag_insight = "It was discovered that Puppet agents incorrectly handled certain kick
  connections in a non-default configuration. An attacker on an authenticated
  client could use this issue to possibly execute arbitrary code.
  (CVE-2013-1653)

  It was discovered that Puppet incorrectly handled certain catalog requests.
  An attacker on an authenticated client could use this issue to possibly
  execute arbitrary code on the master. (CVE-2013-1640)
  
  It was discovered that Puppet incorrectly handled certain client requests.
  An attacker on an authenticated client could use this issue to possibly
  perform unauthorized actions. (CVE-2013-1652)
  
  It was discovered that Puppet incorrectly handled certain SSL connections.
  An attacker could use this issue to possibly downgrade connections to
  SSLv2. (CVE-2013-1654)
  
  It was discovered that Puppet incorrectly handled serialized attributes.
  An attacker on an authenticated client could use this issue to possibly
  cause a denial of service, or execute arbitrary. (CVE-2013-1655)
  
  It was discovered that Puppet incorrectly handled submitted reports.
  An attacker on an authenticated node could use this issue to possibly
  submit a report for any other node. (CVE-2013-2275)";


tag_affected = "puppet on Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 11.10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1759-1/");
  script_id(841361);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-03-15 10:06:08 +0530 (Fri, 15 Mar 2013)");
  script_cve_id("CVE-2013-1653", "CVE-2013-1640", "CVE-2013-1652", "CVE-2013-1654",
                "CVE-2013-1655", "CVE-2013-2275");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1759-1");
  script_name("Ubuntu Update for puppet USN-1759-1");

  script_summary("Check for the Version of puppet");
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

  if ((res = isdpkgvuln(pkg:"puppet-common", ver:"2.7.11-1ubuntu2.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"puppet-common", ver:"2.7.1-1ubuntu3.8", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"puppet-common", ver:"2.7.18-1ubuntu1.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
