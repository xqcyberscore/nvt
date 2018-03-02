###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_ccef1ced42_gimp_fc26.nasl 8998 2018-03-01 12:47:58Z cfischer $
#
# Fedora Update for gimp FEDORA-2018-ccef1ced42
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.874171");
  script_version("$Revision: 8998 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-01 13:47:58 +0100 (Thu, 01 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-02-28 08:40:47 +0100 (Wed, 28 Feb 2018)");
  script_cve_id("CVE-2017-17784", "CVE-2017-17785", "CVE-2017-17786", "CVE-2017-17787", 
                "CVE-2017-17788", "CVE-2017-17789");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for gimp FEDORA-2018-ccef1ced42");
  script_tag(name: "summary", value: "Check the version of gimp");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "GIMP (GNU Image Manipulation Program) is a 
powerful image composition and editing program, which can be extremely useful for 
creating logos and other graphics for webpages. GIMP has many of the tools and 
filters you would expect to find in similar commercial offerings, and some 
interesting extras as well. GIMP provides a large image manipulation toolbox, 
including channel operations and layers, effects, sub-pixel imaging and 
anti-aliasing, and conversions, all with multi-level undo.
");
  script_tag(name: "affected", value: "gimp on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-ccef1ced42");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MP5AWS3ANA7XBBGT27RH23QM6IR2ZW3H");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.8.22~3.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
