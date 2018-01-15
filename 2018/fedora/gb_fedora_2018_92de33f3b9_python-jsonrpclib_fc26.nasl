###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_92de33f3b9_python-jsonrpclib_fc26.nasl 8396 2018-01-12 11:39:41Z gveerendra $
#
# Fedora Update for python-jsonrpclib FEDORA-2018-92de33f3b9
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
  script_oid("1.3.6.1.4.1.25623.1.0.874002");
  script_version("$Revision: 8396 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-12 12:39:41 +0100 (Fri, 12 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-11 07:41:04 +0100 (Thu, 11 Jan 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for python-jsonrpclib FEDORA-2018-92de33f3b9");
  script_tag(name: "summary", value: "Check the version of python-jsonrpclib");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "This project is an implementation of 
the JSON-RPC v2.0 specification (backwards-compatible) as a client library, 
for Python 2.7 and Python 3. This version is a fork of jsonrpclib by Josh 
Marshall, usable with Pelix remote services.
");
  script_tag(name: "affected", value: "python-jsonrpclib on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-92de33f3b9");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EPLJ2YN3L6QTRR6HIDMVSTXZK5Y4CYLF");
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

  if ((res = isrpmvuln(pkg:"python-jsonrpclib", rpm:"python-jsonrpclib~0.3.1~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
