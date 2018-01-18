###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for thunderbird RHSA-2013:1269-01
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

if(description)
{
  script_id(871037);
  script_version("$Revision: 8448 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:18:06 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-09-18 10:10:38 +0530 (Wed, 18 Sep 2013)");
  script_cve_id("CVE-2013-1718", "CVE-2013-1722", "CVE-2013-1725", "CVE-2013-1730",
                "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for thunderbird RHSA-2013:1269-01");

  tag_insight = "Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed content. Malicious
content could cause Thunderbird to crash or, potentially, execute arbitrary
code with the privileges of the user running Thunderbird. (CVE-2013-1718,
CVE-2013-1722, CVE-2013-1725, CVE-2013-1730, CVE-2013-1732, CVE-2013-1735,
CVE-2013-1736)

A flaw was found in the way Thunderbird handled certain DOM JavaScript
objects. An attacker could use this flaw to make JavaScript client or
add-on code make incorrect, security sensitive decisions. (CVE-2013-1737)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Andre Bargull, Scoobidiver, Bobby Holley,
Reuben Morais, Abhishek Arya, Ms2ger, Sachin Shinde, Aki Helin, Nils, and
Boris Zbarsky as the original reporters of these issues.

Note: All of the above issues cannot be exploited by a specially-crafted
HTML mail message as JavaScript is disabled by default for mail messages.
They could be exploited another way in Thunderbird, for example, when
viewing the full remote content of an RSS feed.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 17.0.9 ESR, which corrects these issues. After
installing the update, Thunderbird must be restarted for the changes to
take effect.
";

  tag_affected = "thunderbird on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "RHSA", value: "2013:1269-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2013-September/msg00029.html");
  script_tag(name: "summary" , value: "Check for the Version of thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~17.0.9~1.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~17.0.9~1.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
