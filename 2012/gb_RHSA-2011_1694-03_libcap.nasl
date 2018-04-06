###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for libcap RHSA-2011:1694-03
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
tag_insight = "The libcap packages provide a library and tools for getting and setting
  POSIX capabilities.

  It was found that capsh did not change into the new root when using the
  &quot;--chroot&quot; option. An application started via the &quot;capsh --chroot&quot; command
  could use this flaw to escape the chroot restrictions. (CVE-2011-4099)

  This update also fixes the following bug:

  * Previously, the libcap packages did not contain the capsh(1) manual page.
  With this update, the capsh(1) manual page is included. (BZ#730957)

  All libcap users are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.";

tag_affected = "libcap on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-December/msg00016.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870710");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:51:50 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-4099");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2011:1694-03");
  script_name("RedHat Update for libcap RHSA-2011:1694-03");

  script_tag(name: "summary" , value: "Check for the Version of libcap");
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

  if ((res = isrpmvuln(pkg:"libcap", rpm:"libcap~2.16~5.5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcap-debuginfo", rpm:"libcap-debuginfo~2.16~5.5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcap-devel", rpm:"libcap-devel~2.16~5.5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
