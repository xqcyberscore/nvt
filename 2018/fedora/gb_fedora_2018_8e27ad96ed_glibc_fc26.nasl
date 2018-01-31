###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_8e27ad96ed_glibc_fc26.nasl 8566 2018-01-29 10:57:43Z santu $
#
# Fedora Update for glibc FEDORA-2018-8e27ad96ed
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
  script_oid("1.3.6.1.4.1.25623.1.0.874049");
  script_version("$Revision: 8566 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-29 11:57:43 +0100 (Mon, 29 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-24 07:46:56 +0100 (Wed, 24 Jan 2018)");
  script_cve_id("CVE-2017-15670", "CVE-2017-15671", "CVE-2017-15804", "CVE-2017-16997", 
                "CVE-2018-1000001");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for glibc FEDORA-2018-8e27ad96ed");
  script_tag(name: "summary", value: "Check the version of glibc");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The glibc package contains standard 
libraries which are used by multiple programs on the system. In order to save 
disk space and memory, as well as to make upgrading easier, common system code 
is kept in one place and shared between programs. This particular package
contains the most important sets of shared libraries: the standard C library 
and the standard math library. Without these two libraries, a Linux system 
will not function.");
  script_tag(name: "affected", value: "glibc on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-8e27ad96ed");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DPS2FAZMTBQWO2VPJPE4GF3F4NCMKJUY");
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

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.25~13.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
