###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for freeipa FEDORA-2016-ca1d1e1dc1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.872170");
  script_version("$Revision: 9543 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-20 03:56:24 +0200 (Fri, 20 Apr 2018) $");
  script_tag(name:"creation_date", value:"2016-12-20 06:00:59 +0100 (Tue, 20 Dec 2016)");
  script_cve_id("CVE-2016-9575", "CVE-2016-7030");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for freeipa FEDORA-2016-ca1d1e1dc1");
  script_tag(name: "summary", value: "Check the version of freeipa");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "IPA is an integrated solution to provide
  centrally managed Identity (users, hosts, services), Authentication (SSO,
  2FA), and Authorization (host access control, SELinux user roles, services).
  The solution provides features for further integration with Linux based
  clients (SUDO, automount) and integration with Active Directory based
  infrastructures (Trusts).");

  script_tag(name: "affected", value: "freeipa on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2016-ca1d1e1dc1");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OFNZDKBCMQORSSIRWJNG7KT7ZJF53OPJ");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"freeipa", rpm:"freeipa~4.4.3~1.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
