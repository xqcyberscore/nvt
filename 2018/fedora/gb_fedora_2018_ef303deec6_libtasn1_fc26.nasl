###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_ef303deec6_libtasn1_fc26.nasl 8811 2018-02-14 12:41:44Z cfischer $
#
# Fedora Update for libtasn1 FEDORA-2018-ef303deec6
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
  script_oid("1.3.6.1.4.1.25623.1.0.874106");
  script_version("$Revision: 8811 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-14 13:41:44 +0100 (Wed, 14 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-07 08:09:05 +0100 (Wed, 07 Feb 2018)");
  script_cve_id("CVE-2018-6003");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for libtasn1 FEDORA-2018-ef303deec6");
  script_tag(name: "summary", value: "Check the version of libtasn1");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "A library that provides Abstract Syntax 
Notation One (ASN.1, as specified by the X.680 ITU-T recommendation) parsing 
and structures management, and Distinguished Encoding Rules (DER, as per X.690) 
encoding and decoding functions.
");
  script_tag(name: "affected", value: "libtasn1 on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-ef303deec6");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UI6DW75M74POCGEY7ILIP63CME4QUUIT");
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

  if ((res = isrpmvuln(pkg:"libtasn1", rpm:"libtasn1~4.13~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
