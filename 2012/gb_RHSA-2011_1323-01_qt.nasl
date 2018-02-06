###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for qt RHSA-2011:1323-01
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
tag_insight = "Qt is a software toolkit that simplifies the task of writing and
  maintaining GUI (Graphical User Interface) applications for the X Window
  System. HarfBuzz is an OpenType text shaping engine.

  A buffer overflow flaw was found in the harfbuzz module in Qt. If a user
  loaded a specially-crafted font file with an application linked against Qt,
  it could cause the application to crash or, possibly, execute arbitrary
  code with the privileges of the user running the application.
  (CVE-2011-3193)

  A buffer overflow flaw was found in the way Qt handled certain gray-scale
  image files. If a user loaded a specially-crafted gray-scale image file
  with an application linked against Qt, it could cause the application to
  crash or, possibly, execute arbitrary code with the privileges of the user
  running the application. (CVE-2011-3194)

  Users of Qt should upgrade to these updated packages, which contain
  backported patches to correct these issues. All running applications linked
  against Qt libraries must be restarted for this update to take effect.";

tag_affected = "qt on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-September/msg00035.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870682");
  script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 8671 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:38:48 +0100 (Mon, 05 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:46:06 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-3193", "CVE-2011-3194");
  script_xref(name: "RHSA", value: "2011:1323-01");
  script_name("RedHat Update for qt RHSA-2011:1323-01");

  script_tag(name: "summary" , value: "Check for the Version of qt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"phonon-backend-gstreamer", rpm:"phonon-backend-gstreamer~4.6.2~17.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt", rpm:"qt~4.6.2~17.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-debuginfo", rpm:"qt-debuginfo~4.6.2~17.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-devel", rpm:"qt-devel~4.6.2~17.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-mysql", rpm:"qt-mysql~4.6.2~17.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-odbc", rpm:"qt-odbc~4.6.2~17.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-postgresql", rpm:"qt-postgresql~4.6.2~17.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-sqlite", rpm:"qt-sqlite~4.6.2~17.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-x11", rpm:"qt-x11~4.6.2~17.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-doc", rpm:"qt-doc~4.6.2~17.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
