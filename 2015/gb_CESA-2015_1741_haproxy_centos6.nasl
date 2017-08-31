###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for haproxy CESA-2015:1741 centos6 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882282");
  script_version("$Revision: 6657 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:50:44 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-09-09 06:27:45 +0200 (Wed, 09 Sep 2015)");
  script_cve_id("CVE-2015-3281");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for haproxy CESA-2015:1741 centos6 ");
  script_tag(name: "summary", value: "Check the version of haproxy");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "HAProxy provides high availability, load balancing, and proxying for TCP
and HTTP-based applications.

An implementation error related to the memory management of request and
responses was found within HAProxy's buffer_slow_realign() function.
An unauthenticated remote attacker could possibly use this flaw to leak
certain memory buffer contents from a past request or session.
(CVE-2015-3281)

All haproxy users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue.
");
  script_tag(name: "affected", value: "haproxy on CentOS 6");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "CESA", value: "2015:1741");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2015-September/021376.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~1.5.4~2.el6_7.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
