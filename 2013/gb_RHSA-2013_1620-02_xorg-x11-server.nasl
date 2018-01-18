###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for xorg-x11-server RHSA-2013:1620-02
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_id(871082);
  script_version("$Revision: 8448 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:18:06 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-11-21 10:44:19 +0530 (Thu, 21 Nov 2013)");
  script_cve_id("CVE-2013-1940");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("RedHat Update for xorg-x11-server RHSA-2013:1620-02");

  tag_insight = "X.Org is an open source implementation of the X Window System. It provides
the basic low-level functionality that full-fledged graphical user
interfaces are designed upon.

A flaw was found in the way the X.org X11 server registered new hot plugged
devices. If a local user switched to a different session and plugged in a
new device, input from that device could become available in the previous
session, possibly leading to information disclosure. (CVE-2013-1940)

This issue was found by David Airlie and Peter Hutterer of Red Hat.

This update also fixes the following bugs:

* A previous upstream patch modified the Xephyr X server to be resizeable,
however, it did not enable the resize functionality by default. As a
consequence, X sandboxes were not resizeable on Red Hat Enterprise Linux
6.4 and later. This update enables the resize functionality by default so
that X sandboxes can now be resized as expected. (BZ#915202)

* In Red Hat Enterprise Linux 6, the X Security extension (XC-SECURITY)
has been disabled and replaced by X Access Control Extension (XACE).
However, XACE does not yet include functionality that was previously
available in XC-SECURITY. With this update, XC-SECURITY is enabled in the
xorg-x11-server spec file on Red Hat Enterprise Linux 6. (BZ#957298)

* Upstream code changes to extension initialization accidentally disabled
the GLX extension in Xvfb (the X virtual frame buffer), rendering headless
3D applications not functional. An upstream patch to this problem has been
backported so the GLX extension is enabled again, and applications relying
on this extension work as expected. (BZ#969538)

All xorg-x11-server users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues.
";

  tag_affected = "xorg-x11-server on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "RHSA", value: "2013:1620-02");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2013-November/msg00028.html");
  script_tag(name: "summary" , value: "Check for the Version of xorg-x11-server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xephyr", rpm:"xorg-x11-server-Xephyr~1.13.0~23.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xorg", rpm:"xorg-x11-server-Xorg~1.13.0~23.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-common", rpm:"xorg-x11-server-common~1.13.0~23.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-debuginfo", rpm:"xorg-x11-server-debuginfo~1.13.0~23.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
