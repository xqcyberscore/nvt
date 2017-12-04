###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1209_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for ffmpeg USN-1209-1
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
tag_insight = "It was discovered that FFmpeg incorrectly handled certain malformed ogg
  files. If a user were tricked into opening a crafted ogg file, an attacker
  could cause a denial of service via application crash, or possibly execute
  arbitrary code with the privileges of the user invoking the program. This
  issue only affected Ubuntu 10.10. (CVE-2011-1196)

  It was discovered that FFmpeg incorrectly handled certain malformed AMV
  files. If a user were tricked into opening a crafted AMV file, an attacker
  could cause a denial of service via application crash, or possibly execute
  arbitrary code with the privileges of the user invoking the program. This
  issue only affected Ubuntu 10.10. (CVE-2011-1931)
  
  It was discovered that FFmpeg incorrectly handled certain malformed APE
  files. If a user were tricked into opening a crafted APE file, an attacker
  could cause a denial of service via application crash. (CVE-2011-2161)
  
  Emmanouel Kellinis discovered that FFmpeg incorrectly handled certain
  malformed CAVS files. If a user were tricked into opening a crafted CAVS
  file, an attacker could cause a denial of service via application crash, or
  possibly execute arbitrary code with the privileges of the user invoking
  the program. (CVE-2011-3362)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1209-1";
tag_affected = "ffmpeg on Ubuntu 10.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1209-1/");
  script_id(840750);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "USN", value: "1209-1");
  script_cve_id("CVE-2011-1196", "CVE-2011-1931", "CVE-2011-2161", "CVE-2011-3362");
  script_name("Ubuntu Update for ffmpeg USN-1209-1");

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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libavcodec52", ver:"4:0.5.1-1ubuntu1.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavformat52", ver:"4:0.5.1-1ubuntu1.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"libavcodec52", ver:"4:0.6-2ubuntu6.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavformat52", ver:"4:0.6-2ubuntu6.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
