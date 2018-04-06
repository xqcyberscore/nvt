###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_0314_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# SuSE Update for apache2 openSUSE-SU-2012:0314-1 (apache2)
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
tag_insight = "This update of apache2 fixes regressions and several
  security problems:

  bnc#728876, fix graceful reload

  bnc#741243, CVE-2012-0031: Fixed a scoreboard corruption
  (shared mem segment) by child causes crash of privileged
  parent (invalid free()) during shutdown.

  bnc#743743, CVE-2012-0053: Fixed an issue in error
  responses that could expose &quot;httpOnly&quot; cookies when no
  custom ErrorDocument is specified for status code 400&quot;.

  bnc#738855, CVE-2007-6750: The &quot;mod_reqtimeout&quot; module was
  backported from Apache 2.2.21 to help mitigate the
  &quot;Slowloris&quot; Denial of Service attack.

  You need to enable the &quot;mod_reqtimeout&quot; module in your
  existing apache configuration to make it effective, e.g. in
  the APACHE_MODULES line in /etc/sysconfig/apache2.";

tag_affected = "apache2 on openSUSE 11.4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.850196");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-08-02 20:28:13 +0530 (Thu, 02 Aug 2012)");
  script_cve_id("CVE-2007-6750", "CVE-2012-0031", "CVE-2012-0053");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "openSUSE-SU", value: "2012:0314_1");
  script_name("SuSE Update for apache2 openSUSE-SU-2012:0314-1 (apache2)");

  script_tag(name: "summary" , value: "Check for the Version of apache2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
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

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.2.17~4.13.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-devel", rpm:"apache2-devel~2.2.17~4.13.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-example-certificates", rpm:"apache2-example-certificates~2.2.17~4.13.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-example-pages", rpm:"apache2-example-pages~2.2.17~4.13.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-itk", rpm:"apache2-itk~2.2.17~4.13.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.2.17~4.13.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-utils", rpm:"apache2-utils~2.2.17~4.13.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.2.17~4.13.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.2.17~4.13.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
