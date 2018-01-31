###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_97bdb9ba32_bind_fc27.nasl 8566 2018-01-29 10:57:43Z santu $
#
# Fedora Update for bind FEDORA-2018-97bdb9ba32
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
  script_oid("1.3.6.1.4.1.25623.1.0.874047");
  script_version("$Revision: 8566 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-29 11:57:43 +0100 (Mon, 29 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-24 07:46:52 +0100 (Wed, 24 Jan 2018)");
  script_cve_id("CVE-2017-3145");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for bind FEDORA-2018-97bdb9ba32");
  script_tag(name: "summary", value: "Check the version of bind");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "BIND (Berkeley Internet Name Domain) is 
an implementation of the DNS (Domain Name System) protocols. BIND includes a DNS 
server (named), which resolves host names to IP addresses  a resolver library
(routines for applications to use when interfacing with DNS)  and tools for 
verifying that the DNS server is operating properly.
");
  script_tag(name: "affected", value: "bind on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-97bdb9ba32");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BKBDGWTF7FXCH5QLOOTE3LMORB2DM7GT");
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

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.11.2~1.P1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
