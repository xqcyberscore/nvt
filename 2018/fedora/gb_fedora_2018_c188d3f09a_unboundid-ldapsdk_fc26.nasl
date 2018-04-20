###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_c188d3f09a_unboundid-ldapsdk_fc26.nasl 9543 2018-04-20 01:56:24Z ckuersteiner $
#
# Fedora Update for unboundid-ldapsdk FEDORA-2018-c188d3f09a
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
  script_oid("1.3.6.1.4.1.25623.1.0.874306");
  script_version("$Revision: 9543 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-20 03:56:24 +0200 (Fri, 20 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-03-30 08:46:31 +0200 (Fri, 30 Mar 2018)");
  script_cve_id("CVE-2018-1000134");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for unboundid-ldapsdk FEDORA-2018-c188d3f09a");
  script_tag(name: "summary", value: "Check the version of unboundid-ldapsdk");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The UnboundID LDAP SDK for Java is a fast, 
powerful, user-friendly, and completely free Java library for communicating with 
LDAP directory servers and performing related tasks like reading and writing 
LDIF, encoding and decoding data using base64 and ASN.1 BER, and performing secure 
communication.
");
  script_tag(name: "affected", value: "unboundid-ldapsdk on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-c188d3f09a");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BEPBWWAXZY2U5RA27NFWACPGUBPCF5PU");
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

  if ((res = isrpmvuln(pkg:"unboundid-ldapsdk", rpm:"unboundid-ldapsdk~4.0.5~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
