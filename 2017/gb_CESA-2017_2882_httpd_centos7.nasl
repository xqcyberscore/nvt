###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2017_2882_httpd_centos7.nasl 7455 2017-10-17 09:40:59Z asteins $
#
# CentOS Update for httpd CESA-2017:2882 centos7 
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
  script_oid("1.3.6.1.4.1.25623.1.0.882784");
  script_version("$Revision: 7455 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-17 11:40:59 +0200 (Tue, 17 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-12 10:25:42 +0200 (Thu, 12 Oct 2017)");
  script_cve_id("CVE-2017-9798");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for httpd CESA-2017:2882 centos7 ");
  script_tag(name: "summary", value: "Check the version of httpd");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The httpd packages provide the Apache 
HTTP Server, a powerful, efficient, and extensible web server.

Security Fix(es):

* A use-after-free flaw was found in the way httpd handled invalid and
previously unregistered HTTP methods specified in the Limit directive used
in an .htaccess file. A remote attacker could possibly use this flaw to
disclose portions of the server memory, or cause httpd child process to
crash. (CVE-2017-9798)

Red Hat would like to thank Hanno Bock for reporting this issue.
");
  script_tag(name: "affected", value: "httpd on CentOS 7");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "CESA", value: "2017:2882");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2017-October/022565.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.4.6~67.el7.centos.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.4.6~67.el7.centos.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.4.6~67.el7.centos.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.4.6~67.el7.centos.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ldap", rpm:"mod_ldap~2.4.6~67.el7.centos.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_proxy_html", rpm:"mod_proxy_html~2.4.6~67.el7.centos.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_session", rpm:"mod_session~2.4.6~67.el7.centos.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.4.6~67.el7.centos.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
