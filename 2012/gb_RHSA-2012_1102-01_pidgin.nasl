###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for pidgin RHSA-2012:1102-01
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
tag_insight = "Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously.

  A flaw was found in the way the Pidgin MSN protocol plug-in processed text
  that was not encoded in UTF-8. A remote attacker could use this flaw to
  crash Pidgin by sending a specially-crafted MSN message. (CVE-2012-1178)

  An input validation flaw was found in the way the Pidgin MSN protocol
  plug-in handled MSN notification messages. A malicious server or a remote
  attacker could use this flaw to crash Pidgin by sending a specially-crafted
  MSN notification message. (CVE-2012-2318)

  A buffer overflow flaw was found in the Pidgin MXit protocol plug-in. A
  remote attacker could use this flaw to crash Pidgin by sending a MXit
  message containing specially-crafted emoticon tags. (CVE-2012-3374)

  All Pidgin users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. Pidgin must be restarted for
  this update to take effect.";

tag_affected = "pidgin on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-July/msg00021.html");
  script_id(870795);
  script_version("$Revision: 8285 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 07:29:16 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-07-23 10:46:39 +0530 (Mon, 23 Jul 2012)");
  script_cve_id("CVE-2012-1178", "CVE-2012-2318", "CVE-2012-3374");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2012:1102-01");
  script_name("RedHat Update for pidgin RHSA-2012:1102-01");

  script_tag(name: "summary" , value: "Check for the Version of pidgin");
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

  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.7.9~5.el6.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.7.9~5.el6.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-debuginfo", rpm:"pidgin-debuginfo~2.7.9~5.el6.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
