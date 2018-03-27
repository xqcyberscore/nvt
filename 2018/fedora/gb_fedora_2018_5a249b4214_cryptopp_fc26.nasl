###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_5a249b4214_cryptopp_fc26.nasl 9192 2018-03-23 14:54:27Z cfischer $
#
# Fedora Update for cryptopp FEDORA-2018-5a249b4214
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
  script_oid("1.3.6.1.4.1.25623.1.0.874265");
  script_version("$Revision: 9192 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-23 15:54:27 +0100 (Fri, 23 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-21 15:13:06 +0100 (Wed, 21 Mar 2018)");
  script_cve_id("CVE-2016-7420", "CVE-2016-7544");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for cryptopp FEDORA-2018-5a249b4214");
  script_tag(name: "summary", value: "Check the version of cryptopp");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Crypto++ Library is a free C++ class 
library of cryptographic schemes. See 'http://www.cryptopp.com/' for a list of 
supported algorithms.

One purpose of Crypto++ is to act as a repository of public domain
(not copyrighted) source code. Although the library is copyrighted as a
compilation, the individual files in it are in the public domain.
");
  script_tag(name: "affected", value: "cryptopp on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-5a249b4214");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FI4Z7KUQNNUTW3OL5VH55O3QP7FM53EX");
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

  if ((res = isrpmvuln(pkg:"cryptopp", rpm:"cryptopp~5.6.5~2.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
