###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for xorg-x11 SUSE-SA:2011:016
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "remote code execution";
tag_affected = "xorg-x11 on openSUSE 11.2, openSUSE 11.3, SUSE SLES 9";
tag_insight = "The xrdb helper program of the xorg-x11 package passes untrusted input
  such as hostnames retrieved via DHCP or client hostnames of XDMCP sessions
  to popen() without sanitization.
  Therefore, remote attackers could execute arbitrary commands as root by
  assigning specially crafted hostnames to X11 servers or to XDMCP clients.
  CVE-2011-0465 has been assigned to this issue.";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.850164");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:44:44 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "SUSE-SA", value: "2011-016");
  script_cve_id("CVE-2011-0465");
  script_name("SuSE Update for xorg-x11 SUSE-SA:2011:016");

  script_tag(name:"summary", value:"Check for the Version of xorg-x11");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "openSUSE11.2")
{

  if ((res = isrpmvuln(pkg:"xorg-x11", rpm:"xorg-x11~7.4~35.5.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-xauth", rpm:"xorg-x11-xauth~7.4~35.5.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.3")
{

  if ((res = isrpmvuln(pkg:"xorg-x11", rpm:"xorg-x11~7.5~12.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-xauth", rpm:"xorg-x11-xauth~7.5~12.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
