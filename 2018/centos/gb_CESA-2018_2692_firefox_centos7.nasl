###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_2692_firefox_centos7.nasl 11505 2018-09-20 13:03:00Z santu $
#
# CentOS Update for firefox CESA-2018:2692 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882945");
  script_version("$Revision: 11505 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-20 15:03:00 +0200 (Thu, 20 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-14 07:34:35 +0200 (Fri, 14 Sep 2018)");
  script_cve_id("CVE-2017-16541", "CVE-2018-12376", "CVE-2018-12377", "CVE-2018-12378",
                "CVE-2018-12379");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for firefox CESA-2018:2692 centos7 ");
  script_tag(name:"summary", value:"Check the version of firefox");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open-source web browser,
  designed for standards compliance, performance, and portability.

This update upgrades Firefox to version 60.2.0 ESR.

Security Fix(es):

* Mozilla: Memory safety bugs fixed in Firefox 62 and Firefox ESR 60.2
(CVE-2018-12376)

* Mozilla: Use-after-free in driver timers (CVE-2018-12377)

* Mozilla: Use-after-free in IndexedDB (CVE-2018-12378)

* Mozilla: Proxy bypass using automount and autofs (CVE-2017-16541)

* Mozilla: Out-of-bounds write with malicious MAR file (CVE-2018-12379)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Alex Gaynor, Boris Zbarsky, Christoph Diehl,
Christian Holler, Jason Kratzer, Jed Davis, Tyson Smith, Bogdan Tara, Karl
Tomlinson, Mats Palmgren, Nika Layzell, Ted Campbell, Nils, Zhanjia Song,
and Holger Fuhrmannek as the original reporters.
");
  script_tag(name:"affected", value:"firefox on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2018:2692");
  script_xref(name:"URL" , value:"http://lists.centos.org/pipermail/centos-announce/2018-September/023022.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~60.2.0~1.el7.centos", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
