###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_39051f69b7_freeipa_fc27.nasl 11163 2018-08-30 09:09:48Z santu $
#
# Fedora Update for freeipa FEDORA-2018-39051f69b7
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
  script_oid("1.3.6.1.4.1.25623.1.0.875009");
  script_version("$Revision: 11163 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-30 11:09:48 +0200 (Thu, 30 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-29 07:30:17 +0200 (Wed, 29 Aug 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for freeipa FEDORA-2018-39051f69b7");
  script_tag(name:"summary", value:"Check the version of freeipa");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"IPA is an integrated solution to provide
centrally managed Identity (users, hosts, services), Authentication (SSO, 2FA),
and Authorization (host access control, SELinux user roles, services).
The solution provides features for further integration with Linux based clients
(SUDO, automount) and integration with Active Directory based infrastructures (Trusts).
");
  script_tag(name:"affected", value:"freeipa on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-39051f69b7");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XMPCCZFGWEO3MFOD2SS365NNHABOSL4M");
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

  if ((res = isrpmvuln(pkg:"freeipa-server", rpm:"freeipa-server~4.6.4~2.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeipa-client-common", rpm:"freeipa-client-common~4.6.4~2.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeipa-server-trust-ad", rpm:"freeipa-server-trust-ad~4.6.4~2.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeipa-common", rpm:"freeipa-common~4.6.4~2.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeipa-server-dns", rpm:"freeipa-server-dns~4.6.4~2.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeipa-server-common", rpm:"freeipa-server-common~4.6.4~2.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeipa-client", rpm:"freeipa-client~4.6.4~2.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeipa-python-compat", rpm:"freeipa-python-compat~4.6.4~2.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
