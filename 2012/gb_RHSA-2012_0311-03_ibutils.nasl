###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for ibutils RHSA-2012:0311-03
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
tag_insight = "The ibutils packages provide InfiniBand network and path diagnostics.

  It was found that the ibmssh executable had an insecure relative RPATH
  (runtime library search path) set in the ELF (Executable and Linking
  Format) header. A local user able to convince another user to run ibmssh in
  an attacker-controlled directory could run arbitrary code with the
  privileges of the victim. (CVE-2008-3277)

  This update also fixes the following bug:

  * Under certain circumstances, the &quot;ibdiagnet -r&quot; command could suffer from
  memory corruption and terminate with a &quot;double free or corruption&quot; message
  and a backtrace. With this update, the correct memory management function
  is used to prevent the corruption. (BZ#711779)

  All users of ibutils are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues.";

tag_affected = "ibutils on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-February/msg00045.html");
  script_id(870565);
  script_version("$Revision: 8285 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 07:29:16 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-02-21 18:57:32 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2008-3277");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2012:0311-03");
  script_name("RedHat Update for ibutils RHSA-2012:0311-03");

  script_tag(name: "summary" , value: "Check for the Version of ibutils");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"ibutils", rpm:"ibutils~1.2~11.2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibutils-debuginfo", rpm:"ibutils-debuginfo~1.2~11.2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibutils-devel", rpm:"ibutils-devel~1.2~11.2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibutils-libs", rpm:"ibutils-libs~1.2~11.2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
