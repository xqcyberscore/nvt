###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mingw-openssl FEDORA-2013-4403
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "The OpenSSL toolkit provides support for secure communications between
  machines. OpenSSL includes a certificate management tool and shared
  libraries which provide various cryptographic algorithms and
  protocols.

  This package contains Windows (MinGW) libraries and development tools.";


tag_affected = "mingw-openssl on Fedora 18";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(865516);
  script_version("$Revision: 8448 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:18:06 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-04-05 13:43:08 +0530 (Fri, 05 Apr 2013)");
  script_cve_id("CVE-2013-0169", "CVE-2012-4929");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_name("Fedora Update for mingw-openssl FEDORA-2013-4403");

  script_xref(name: "FEDORA", value: "2013-4403");
  script_xref(name: "URL" , value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-April/101366.html");
  script_tag(name: "summary" , value: "Check for the Version of mingw-openssl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"mingw-openssl", rpm:"mingw-openssl~1.0.1e~1.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
