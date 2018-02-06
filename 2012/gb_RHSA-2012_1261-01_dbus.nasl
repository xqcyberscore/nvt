###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for dbus RHSA-2012:1261-01
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
tag_insight = "D-Bus is a system for sending messages between applications. It is used for
  the system-wide message bus service and as a per-user-login-session
  messaging facility.

  It was discovered that the D-Bus library honored environment settings even
  when running with elevated privileges. A local attacker could possibly use
  this flaw to escalate their privileges, by setting specific environment
  variables before running a setuid or setgid application linked against the
  D-Bus library (libdbus). (CVE-2012-3524)

  Note: With this update, libdbus ignores environment variables when used by
  setuid or setgid applications. The environment is not ignored when an
  application gains privileges via file system capabilities; however, no
  application shipped in Red Hat Enterprise Linux 6 gains privileges via file
  system capabilities.

  Red Hat would like to thank Sebastian Krahmer of the SUSE Security Team for
  reporting this issue.

  All users are advised to upgrade to these updated packages, which contain a
  backported patch to correct this issue. For the update to take effect, all
  running instances of dbus-daemon and all running applications using the
  libdbus library must be restarted, or the system rebooted.";

tag_affected = "dbus on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-September/msg00016.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870830");
  script_version("$Revision: 8671 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:38:48 +0100 (Mon, 05 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-09-17 16:41:48 +0530 (Mon, 17 Sep 2012)");
  script_cve_id("CVE-2012-3524");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2012:1261-01");
  script_name("RedHat Update for dbus RHSA-2012:1261-01");

  script_tag(name: "summary" , value: "Check for the Version of dbus");
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

  if ((res = isrpmvuln(pkg:"dbus", rpm:"dbus~1.2.24~7.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-debuginfo", rpm:"dbus-debuginfo~1.2.24~7.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-devel", rpm:"dbus-devel~1.2.24~7.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-libs", rpm:"dbus-libs~1.2.24~7.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-x11", rpm:"dbus-x11~1.2.24~7.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
