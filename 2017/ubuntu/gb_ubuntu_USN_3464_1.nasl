###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3464_1.nasl 7601 2017-10-31 06:41:32Z santu $
#
# Ubuntu Update for wget USN-3464-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843351");
  script_version("$Revision: 7601 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-31 07:41:32 +0100 (Tue, 31 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-27 14:32:33 +0200 (Fri, 27 Oct 2017)");
  script_cve_id("CVE-2017-13089", "CVE-2017-13090", "CVE-2016-7098", "CVE-2017-6508");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for wget USN-3464-1");
  script_tag(name: "summary", value: "Check the version of wget");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value: "Antti Levomki, Christian Jalio, and Joonas 
  Pihlaja discovered that Wget incorrectly handled certain HTTP responses. A 
  remote attacker could use this issue to cause Wget to crash, resulting in a 
  denial of service, or possibly execute arbitrary code. (CVE-2017-13089, 
  CVE-2017-13090) Dawid Golunski discovered that Wget incorrectly handled 
  recursive or mirroring mode. A remote attacker could possibly use this issue to 
  bypass intended access list restrictions. (CVE-2016-7098) Orange Tsai discovered 
  that Wget incorrectly handled CRLF sequences in HTTP headers. A remote attacker 
  could possibly use this issue to inject arbitrary HTTP headers. 
  (CVE-2017-6508)"); 
  script_tag(name: "affected", value: "wget on Ubuntu 17.04 ,
  Ubuntu 16.04 LTS ,
  Ubuntu 14.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "USN", value: "3464-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-3464-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"wget", ver:"1.15-1ubuntu1.14.04.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU17.04")
{

  if ((res = isdpkgvuln(pkg:"wget", ver:"1.18-2ubuntu1.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"wget", ver:"1.17.1-1ubuntu1.3", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
