###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_3260-01_samba.nasl 8247 2017-12-26 13:32:16Z cfischer $
#
# RedHat Update for samba RHSA-2017:3260-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.812301");
  script_version("$Revision: 8247 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 14:32:16 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-27 07:37:11 +0100 (Mon, 27 Nov 2017)");
  script_cve_id("CVE-2017-14746", "CVE-2017-15275");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for samba RHSA-2017:3260-01");
  script_tag(name: "summary", value: "Check the version of samba");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Samba is an open-source implementation of
the Server Message Block (SMB) protocol and the related Common Internet File
System (CIFS) protocol, which allow PC-compatible machines to share files,
printers, and various information.

Security Fix(es):

* A use-after-free flaw was found in the way samba servers handled certain
SMB1 requests. An unauthenticated attacker could send specially-crafted
SMB1 requests to cause the server to crash or execute arbitrary code.
(CVE-2017-14746)

* A memory disclosure flaw was found in samba. An attacker could retrieve
parts of server memory, which could contain potentially sensitive data, by
sending specially-crafted requests to the samba server. (CVE-2017-15275)

Red Hat would like to thank the Samba project for reporting these issues.
Upstream acknowledges Yihan Lian and Zhibin Hu (Qihoo 360 GearTeam) as the
original reporter of CVE-2017-14746  and Volker Lendecke (SerNet and the
Samba Team) as the original reporter of CVE-2017-15275.
");
  script_tag(name: "affected", value: "samba on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2017:3260-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2017-November/msg00030.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~4.6.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~4.6.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwbclient", rpm:"libwbclient~4.6.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~4.6.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.6.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client-libs", rpm:"samba-client-libs~4.6.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common-libs", rpm:"samba-common-libs~4.6.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common-tools", rpm:"samba-common-tools~4.6.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~4.6.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-krb5-printing", rpm:"samba-krb5-printing~4.6.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.6.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-python", rpm:"samba-python~4.6.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.6.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~4.6.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind-modules", rpm:"samba-winbind-modules~4.6.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
