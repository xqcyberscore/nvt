###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for xorg-x11-server RHSA-2012:0939-04
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
tag_insight = "X.Org is an open source implementation of the X Window System. It provides
  the basic low-level functionality that full-fledged graphical user
  interfaces are designed upon.

  A flaw was found in the way the X.Org server handled lock files. A local
  user with access to the system console could use this flaw to determine the
  existence of a file in a directory not accessible to the user, via a
  symbolic link attack. (CVE-2011-4028)

  A race condition was found in the way the X.Org server managed temporary
  lock files. A local attacker could use this flaw to perform a symbolic link
  attack, allowing them to make an arbitrary file world readable, leading to
  the disclosure of sensitive information. (CVE-2011-4029)

  Red Hat would like to thank the researcher with the nickname vladz for
  reporting these issues.

  This update also fixes the following bugs:

  * Prior to this update, the KDE Display Manager (KDM) could pass invalid
  24bpp pixmap formats to the X server. As a consequence, the X server could
  unexpectedly abort. This update modifies the underlying code to pass the
  correct formats. (BZ#651934, BZ#722860)
  
  * Prior to this update, absolute input devices, like the stylus of a
  graphic tablet, could become unresponsive in the right-most or bottom-most
  screen if the X server was configured as a multi-screen setup through
  multiple &quot;Device&quot; sections in the xorg.conf file. This update changes the
  screen crossing behavior so that absolute devices are always mapped across
  all screens. (BZ#732467)
  
  * Prior to this update, the misleading message &quot;Session active, not
  inhibited, screen idle. If you see this test, your display server is broken
  and you should notify your distributor.&quot; could be displayed after resuming
  the system or re-enabling the display, and included a URL to an external
  web page. This update removes this message. (BZ#748704)
  
  * Prior to this update, the erroneous input handling code of the Xephyr
  server disabled screens on a screen crossing event. The focus was only on
  the screen where the mouse was located and only this screen was updated
  when the Xephyr nested X server was configured in a multi-screen setup.
  This update removes this code and Xephyr now correctly updates screens in
  multi-screen setups. (BZ#757792)
  
  * Prior to this update, raw events did not contain relative axis values. As
  a consequence, clients which relied on relative values for functioning did
   ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "xorg-x11-server on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-June/msg00036.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870775");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-06-22 10:26:29 +0530 (Fri, 22 Jun 2012)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2011-4028", "CVE-2011-4029");
  script_xref(name: "RHSA", value: "2012:0939-04");
  script_name("RedHat Update for xorg-x11-server RHSA-2012:0939-04");

  script_tag(name: "summary" , value: "Check for the Version of xorg-x11-server");
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

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xephyr", rpm:"xorg-x11-server-Xephyr~1.10.6~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xorg", rpm:"xorg-x11-server-Xorg~1.10.6~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-common", rpm:"xorg-x11-server-common~1.10.6~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-debuginfo", rpm:"xorg-x11-server-debuginfo~1.10.6~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
