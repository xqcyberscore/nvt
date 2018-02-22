###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_828f8a8fc6_glibc_fc27.nasl 8893 2018-02-21 06:36:27Z cfischer $
#
# Fedora Update for glibc FEDORA-2017-828f8a8fc6
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
  script_oid("1.3.6.1.4.1.25623.1.0.873969");
  script_version("$Revision: 8893 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-21 07:36:27 +0100 (Wed, 21 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-01-05 23:59:14 +0100 (Fri, 05 Jan 2018)");
  script_cve_id("CVE-2017-1000408", "CVE-2017-1000409");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for glibc FEDORA-2017-828f8a8fc6");
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
  script_tag(name: "affected", value: "glibc on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-828f8a8fc6");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TNORT4UZOWS4VTTJZPEVYXRGJ3NKDCLH");
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

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.26~21.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
