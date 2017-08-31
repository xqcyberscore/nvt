###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_7eaec3353d_poppler_fc25.nasl 6800 2017-07-26 06:58:22Z cfischer $
#
# Fedora Update for poppler FEDORA-2017-7eaec3353d
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
  script_oid("1.3.6.1.4.1.25623.1.0.872897");
  script_version("$Revision: 6800 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-26 08:58:22 +0200 (Wed, 26 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-07-21 07:33:40 +0200 (Fri, 21 Jul 2017)");
  script_cve_id("CVE-2017-7515", "CVE-2017-9775", "CVE-2017-9776", "CVE-2017-9865", 
                "CVE-2017-9406", "CVE-2017-9408");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for poppler FEDORA-2017-7eaec3353d");
  script_tag(name: "summary", value: "Check the version of poppler");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Poppler, a PDF rendering library, is a fork 
of the xpdf PDF viewer developed by Derek Noonburg of Glyph and Cog, LLC.");
  script_tag(name: "affected", value: "poppler on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-7eaec3353d");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UG6XKWCGBOMEV4Q27UHKSHKAD6ZQTWIX");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.45.0~5.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
