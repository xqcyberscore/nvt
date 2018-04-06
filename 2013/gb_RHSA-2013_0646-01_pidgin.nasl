###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for pidgin RHSA-2013:0646-01
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
tag_insight = "Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously.

  A stack-based buffer overflow flaw was found in the Pidgin MXit protocol
  plug-in. A malicious server or a remote attacker could use this flaw to
  crash Pidgin by sending a specially-crafted HTTP request. (CVE-2013-0272)

  A buffer overflow flaw was found in the Pidgin Sametime protocol plug-in.
  A malicious server or a remote attacker could use this flaw to crash Pidgin
  by sending a specially-crafted username. (CVE-2013-0273)

  A buffer overflow flaw was found in the way Pidgin processed certain UPnP
  responses. A remote attacker could send a specially-crafted UPnP response
  that, when processed, would crash Pidgin. (CVE-2013-0274)

  Red Hat would like to thank the Pidgin project for reporting the above
  issues. Upstream acknowledges Daniel Atallah as the original reporter of
  CVE-2013-0272.

  All Pidgin users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. Pidgin must be restarted for
  this update to take effect.";


tag_affected = "pidgin on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2013-March/msg00049.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870963");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-03-15 09:50:00 +0530 (Fri, 15 Mar 2013)");
  script_cve_id("CVE-2013-0272", "CVE-2013-0273", "CVE-2013-0274");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2013:0646-01");
  script_name("RedHat Update for pidgin RHSA-2013:0646-01");

  script_tag(name: "summary" , value: "Check for the Version of pidgin");
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

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.7.9~10.el6_4.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.7.9~10.el6_4.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-debuginfo", rpm:"pidgin-debuginfo~2.7.9~10.el6_4.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
