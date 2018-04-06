###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kdelibs CESA-2011:1385 centos5 x86_64
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The kdelibs and kdelibs3 packages provide libraries for the K Desktop
  Environment (KDE).

  An input sanitization flaw was found in the KSSL (KDE SSL Wrapper) API. An
  attacker could supply a specially-crafted SSL certificate (for example, via
  a web page) to an application using KSSL, such as the Konqueror web
  browser, causing misleading information to be presented to the user,
  possibly tricking them into accepting the certificate as valid.
  (CVE-2011-3365)
  
  Users should upgrade to these updated packages, which contain a backported
  patch to correct this issue. The desktop must be restarted (log out, then
  log back in) for this update to take effect.";

tag_affected = "kdelibs on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-October/018124.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881296");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:19:31 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-3365");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "CESA", value: "2011:1385");
  script_name("CentOS Update for kdelibs CESA-2011:1385 centos5 x86_64");

  script_tag(name: "summary" , value: "Check for the Version of kdelibs");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"kdelibs", rpm:"kdelibs~3.5.4~26.el5.centos.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs-apidocs", rpm:"kdelibs-apidocs~3.5.4~26.el5.centos.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs-devel", rpm:"kdelibs-devel~3.5.4~26.el5.centos.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
