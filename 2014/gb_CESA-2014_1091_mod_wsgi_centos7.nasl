###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for mod_wsgi CESA-2014:1091 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882016");
  script_version("$Revision: 9373 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:57:18 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-09-10 06:20:36 +0200 (Wed, 10 Sep 2014)");
  script_cve_id("CVE-2014-0240");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for mod_wsgi CESA-2014:1091 centos7 ");
  script_tag(name: "insight", value: "The mod_wsgi adapter is an Apache module
that provides a WSGI-compliant interface for hosting Python-based web
applications within Apache.

It was found that mod_wsgi did not properly drop privileges if the call to
setuid() failed. If mod_wsgi was set up to allow unprivileged users to run
WSGI applications, a local user able to run a WSGI application could
possibly use this flaw to escalate their privileges on the system.
(CVE-2014-0240)

Note: mod_wsgi is not intended to provide privilege separation for WSGI
applications. Systems relying on mod_wsgi to limit or sandbox the
privileges of mod_wsgi applications should migrate to a different solution
with proper privilege separation.

Red Hat would like to thank Graham Dumpleton for reporting this issue.
Upstream acknowledges Rbert Kisteleki as the original reporter.

All mod_wsgi users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue.
");
  script_tag(name: "affected", value: "mod_wsgi on CentOS 7");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name: "CESA", value: "2014:1091");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2014-August/020506.html");
  script_tag(name:"summary", value:"Check for the Version of mod_wsgi");
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

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"mod_wsgi", rpm:"mod_wsgi~3.4~12.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
