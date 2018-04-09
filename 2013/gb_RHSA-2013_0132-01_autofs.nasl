###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for autofs RHSA-2013:0132-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The autofs utility controls the operation of the automount daemon. The
  automount daemon automatically mounts and unmounts file systems.

  A bug fix included in RHBA-2012:0264 introduced a denial of service flaw in
  autofs. When using autofs with LDAP, a local user could use this flaw to
  crash autofs, preventing future mount requests from being processed until
  the autofs service was restarted. Note: This flaw did not impact existing
  mounts (except for preventing mount expiration). (CVE-2012-2697)

  Red Hat would like to thank Ray Rocker for reporting this issue.

  This update also fixes the following bugs:

  * The autofs init script sometimes timed out waiting for the automount
  daemon to exit and returned a shutdown failure if the daemon failed to exit
  in time. To resolve this problem, the amount of time that the init script
  waits for the daemon has been increased to allow for cases where servers
  are slow to respond or there are many active mounts. (BZ#585058)

  * Due to an omission when backporting a change, autofs attempted to
  download the entire LDAP map at startup. This mistake has now been
  corrected. (BZ#767428)

  All users of autofs are advised to upgrade to this updated package, which
  contains backported patches to correct these issues and add this
  enhancement.

   Description truncated, for more information please check the Reference URL";


tag_affected = "autofs on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2013-January/msg00015.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870886");
  script_version("$Revision: 9372 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:56:37 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-01-11 16:42:44 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2012-2697");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "RHSA", value: "2013:0132-01");
  script_name("RedHat Update for autofs RHSA-2013:0132-01");

  script_tag(name:"summary", value:"Check for the Version of autofs");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"autofs", rpm:"autofs~5.0.1~0.rc2.177.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"autofs-debuginfo", rpm:"autofs-debuginfo~5.0.1~0.rc2.177.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
