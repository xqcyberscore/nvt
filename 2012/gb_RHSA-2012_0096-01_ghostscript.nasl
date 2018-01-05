###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for ghostscript RHSA-2012:0096-01
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
tag_insight = "Ghostscript is a set of software that provides a PostScript interpreter, a
  set of C procedures (the Ghostscript library, which implements the graphics
  capabilities in the PostScript language) and an interpreter for Portable
  Document Format (PDF) files.

  Ghostscript included the current working directory in its library search
  path by default. If a user ran Ghostscript without the option in an
  attacker-controlled directory containing a specially-crafted PostScript
  library file, it could cause Ghostscript to execute arbitrary PostScript
  code. With this update, Ghostscript no longer searches the current working
  directory for library files by default. (CVE-2010-4820)

  Note: The fix for CVE-2010-4820 could possibly break existing
  configurations. To use the previous, vulnerable behavior, run Ghostscript
  with the &quot;-P&quot; option (to always search the current working directory
  first).

  A flaw was found in the way Ghostscript interpreted PostScript Type 1 and
  PostScript Type 2 font files. An attacker could create a specially-crafted
  PostScript Type 1 or PostScript Type 2 font file that, when interpreted,
  could cause Ghostscript to crash or, potentially, execute arbitrary code.
  (CVE-2010-4054)

  Users of Ghostscript are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues.";

tag_affected = "ghostscript on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-February/msg00015.html");
  script_id(870541);
  script_version("$Revision: 8295 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 07:29:18 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-02-03 11:24:27 +0530 (Fri, 03 Feb 2012)");
  script_cve_id("CVE-2010-4054", "CVE-2010-4820");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2012:0096-01");
  script_name("RedHat Update for ghostscript RHSA-2012:0096-01");

  script_tag(name: "summary" , value: "Check for the Version of ghostscript");
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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~7.07~33.13.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~7.07~33.13.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~7.07~33.13.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-gtk", rpm:"ghostscript-gtk~7.07~33.13.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
