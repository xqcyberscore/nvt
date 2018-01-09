###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_93b6236635_erlang_fc26.nasl 8307 2018-01-07 18:51:31Z asteins $
#
# Fedora Update for erlang FEDORA-2017-93b6236635
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
  script_oid("1.3.6.1.4.1.25623.1.0.873913");
  script_version("$Revision: 8307 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-07 19:51:31 +0100 (Sun, 07 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-12-14 11:43:25 +0100 (Thu, 14 Dec 2017)");
  script_cve_id("CVE-2017-1000385");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for erlang FEDORA-2017-93b6236635");
  script_tag(name: "summary", value: "Check the version of erlang");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Erlang is a general-purpose programming 
language and runtime environment. Erlang has built-in support for concurrency, 
distribution and fault tolerance. Erlang is used in several large 
telecommunication systems from Ericsson.
");
  script_tag(name: "affected", value: "erlang on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-93b6236635");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/F4AG4IM4VVPLELU2UCIR3S5HARXUV774");
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

  if ((res = isrpmvuln(pkg:"erlang", rpm:"erlang~19.3.6.4~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
