###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for mod_auth_mellon CESA-2014:1803 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882076");
  script_version("$Revision: 6656 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:49:38 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-11-06 06:19:00 +0100 (Thu, 06 Nov 2014)");
  script_cve_id("CVE-2014-8566", "CVE-2014-8567");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_name("CentOS Update for mod_auth_mellon CESA-2014:1803 centos6 ");

  script_tag(name: "summary", value: "Check the version of mod_auth_mellon");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "mod_auth_mellon provides a SAML 2.0
authentication module for the Apache HTTP Server.

An information disclosure flaw was found in mod_auth_mellon's session
handling that could lead to sessions overlapping in memory. A remote
attacker could potentially use this flaw to obtain data from another user's
session. (CVE-2014-8566)

It was found that uninitialized data could be read when processing a user's
logout request. By attempting to log out, a user could possibly cause the
Apache HTTP Server to crash. (CVE-2014-8567)

Red Hat would like to thank the mod_auth_mellon team for reporting these
issues. Upstream acknowledges Matthew Slowe as the original reporter of
CVE-2014-8566.

All users of mod_auth_mellon are advised to upgrade to this updated
package, which contains a backported patch to correct these issues.
");
  script_tag(name: "affected", value: "mod_auth_mellon on CentOS 6");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2014:1803");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2014-November/020737.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"mod_auth_mellon", rpm:"mod_auth_mellon~0.8.0~3.el6_6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
