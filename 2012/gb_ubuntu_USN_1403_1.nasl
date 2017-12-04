###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1403_1.nasl 7960 2017-12-01 06:58:16Z santu $
#
# Ubuntu Update for freetype USN-1403-1
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
tag_insight = "Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed BDF font files. If a user were tricked into using a specially crafted
  font file, a remote attacker could cause FreeType to crash. (CVE-2012-1126)

  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed BDF font files. If a user were tricked into using a specially crafted
  font file, a remote attacker could cause FreeType to crash. (CVE-2012-1127)
  
  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed TrueType font files. If a user were tricked into using a specially
  crafted font file, a remote attacker could cause FreeType to crash.
  (CVE-2012-1128)
  
  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed Type42 font files. If a user were tricked into using a specially
  crafted font file, a remote attacker could cause FreeType to crash.
  (CVE-2012-1129)
  
  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed PCF font files. If a user were tricked into using a specially crafted
  font file, a remote attacker could cause FreeType to crash. (CVE-2012-1130)
  
  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed TrueType font files. If a user were tricked into using a specially
  crafted font file, a remote attacker could cause FreeType to crash.
  (CVE-2012-1131)
  
  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed Type1 font files. If a user were tricked into using a specially
  crafted font file, a remote attacker could cause FreeType to crash.
  (CVE-2012-1132)
  
  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed BDF font files. If a user were tricked into using a specially crafted
  font file, a remote attacker could cause FreeType to crash or possibly execute
  arbitrary code with user privileges. (CVE-2012-1133)
  
  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed Type1 font files. If a user were tricked into using a specially
  crafted font file, a remote attacker could cause FreeType to crash or possibly
  execute arbitrary code with user privileges. (CVE-2012-1134)
  
  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed TrueType font files. If a user were tricked into using a specially
  crafted font file, a remote attacker could cause FreeType to crash.
  (CVE-2012-1135)
  
  Mateusz Jurczyk discovere ... 

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1403-1";
tag_affected = "freetype on Ubuntu 11.10 ,
  Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS ,
  Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1403-1/");
  script_id(840959);
  script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 7960 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:58:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-03-26 14:17:20 +0530 (Mon, 26 Mar 2012)");
  script_cve_id("CVE-2012-1126", "CVE-2012-1127", "CVE-2012-1128", "CVE-2012-1129", "CVE-2012-1130", "CVE-2012-1131", "CVE-2012-1132", "CVE-2012-1133", "CVE-2012-1134", "CVE-2012-1135", "CVE-2012-1136", "CVE-2012-1137", "CVE-2012-1138", "CVE-2012-1139", "CVE-2012-1140", "CVE-2012-1141", "CVE-2012-1142", "CVE-2012-1143", "CVE-2012-1144");
  script_xref(name: "USN", value: "1403-1");
  script_name("Ubuntu Update for freetype USN-1403-1");

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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"libfreetype6", ver:"2.4.2-2ubuntu0.4", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libfreetype6", ver:"2.3.11-1ubuntu2.6", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"libfreetype6", ver:"2.4.4-2ubuntu1.2", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"libfreetype6", ver:"2.4.4-1ubuntu2.3", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libfreetype6", ver:"2.3.5-1ubuntu4.8.04.9", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
