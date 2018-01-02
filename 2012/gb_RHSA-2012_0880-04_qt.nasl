###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for qt RHSA-2012:0880-04
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
  (CVE-2011-3922)

  A flaw was found in the way Qt handled X.509 certificates with IP address
  wildcards. An attacker able to obtain a certificate with a Common Name
  containing an IP wildcard could possibly use this flaw to impersonate an
  SSL server to client applications that are using Qt. This update also
  introduces more strict handling for hostname wildcard certificates by
  disallowing the wildcard character to match more than one hostname
  component. (CVE-2010-5076)

  This update also fixes the following bugs:

  * The Phonon API allowed premature freeing of the media object.
  Consequently, GStreamer could terminate unexpectedly as it failed to access
  the released media object. This update modifies the underlying Phonon API
  code and the problem no longer occurs. (BZ#694684)

  * Previously, Qt could output the &quot;Unrecognized OpenGL version&quot; error and
  fall back to OpenGL-version-1 compatibility mode. This happened because Qt
  failed to recognize the version of OpenGL installed on the system if the
  system was using a version of OpenGL released later than the Qt version in
  use. This update adds the code for recognition of OpenGL versions to Qt and
  if the OpenGL version is unknown, Qt assumes that the last-known version of
  OpenGL is available. (BZ#757793)

  * Previously Qt included a compiled-in list of trusted CA (Certificate
  Authority) certificates, that could have been used if Qt failed to open a
  system's ca-bundle.crt file. With this update, Qt no longer includes
  compiled-in CA certificates and only uses the system bundle. (BZ#734444)

  Users of Qt should upgrade to these updated packages, which contain
  backported patches to correct these issues. All running applications linked
  against Qt libraries must be restarted for this update to take effect.";

tag_affected = "qt on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-June/msg00032.html");
  script_id(870761);
  script_version("$Revision: 8253 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-28 07:29:51 +0100 (Thu, 28 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-06-22 10:25:46 +0530 (Fri, 22 Jun 2012)");
  script_cve_id("CVE-2010-5076", "CVE-2011-3922");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2012:0880-04");
  script_name("RedHat Update for qt RHSA-2012:0880-04");

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

  if ((res = isrpmvuln(pkg:"phonon-backend-gstreamer", rpm:"phonon-backend-gstreamer~4.6.2~24.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt", rpm:"qt~4.6.2~24.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-debuginfo", rpm:"qt-debuginfo~4.6.2~24.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-devel", rpm:"qt-devel~4.6.2~24.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-mysql", rpm:"qt-mysql~4.6.2~24.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-odbc", rpm:"qt-odbc~4.6.2~24.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-postgresql", rpm:"qt-postgresql~4.6.2~24.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-sqlite", rpm:"qt-sqlite~4.6.2~24.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-x11", rpm:"qt-x11~4.6.2~24.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-doc", rpm:"qt-doc~4.6.2~24.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
