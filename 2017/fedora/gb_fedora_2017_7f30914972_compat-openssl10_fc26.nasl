###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_7f30914972_compat-openssl10_fc26.nasl 7992 2017-12-05 08:34:22Z teissa $
#
# Fedora Update for compat-openssl10 FEDORA-2017-7f30914972
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
  script_oid("1.3.6.1.4.1.25623.1.0.873785");
  script_version("$Revision: 7992 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-05 09:34:22 +0100 (Tue, 05 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-23 08:15:39 +0100 (Thu, 23 Nov 2017)");
  script_cve_id("CVE-2017-3735", "CVE-2017-3736");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for compat-openssl10 FEDORA-2017-7f30914972");
  script_tag(name: "summary", value: "Check the version of compat-openssl10");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The OpenSSL toolkit provides support for 
secure communications between machines. This version of OpenSSL package 
contains only the libraries and is provided for compatibility with previous 
releases and software that does not support compilation with OpenSSL-1.1.
");
  script_tag(name: "affected", value: "compat-openssl10 on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-7f30914972");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UHZBQOKSUMHZLCHSSHRY5XRKZ32UZ7UN");
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

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"compat-openssl10", rpm:"compat-openssl10~1.0.2m~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
