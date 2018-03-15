###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_8d544ee879_zziplib_fc27.nasl 9094 2018-03-14 07:52:16Z cfischer $
#
# Fedora Update for zziplib FEDORA-2018-8d544ee879
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
  script_oid("1.3.6.1.4.1.25623.1.0.874137");
  script_version("$Revision: 9094 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-14 08:52:16 +0100 (Wed, 14 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-02-21 08:52:16 +0100 (Wed, 21 Feb 2018)");
  script_cve_id("CVE-2018-6869", "CVE-2018-6484");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for zziplib FEDORA-2018-8d544ee879");
  script_tag(name: "summary", value: "Check the version of zziplib");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The zziplib library is intentionally 
lightweight, it offers the ability to easily extract data from files archived 
in a single zip file. Applications can bundle files into a single zip archive 
and access them. The implementation is based only on the (free) subset of 
compression with the zlib algorithm which is actually used by the zip/unzip tools.
");
  script_tag(name: "affected", value: "zziplib on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-8d544ee879");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/T5F2Q7GQYRYWHMTEF2OKBIHBBFV6SZBY");
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

  if ((res = isrpmvuln(pkg:"zziplib", rpm:"zziplib~0.13.68~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
