###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for json-c RHSA-2014:0703-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871185");
  script_version("$Revision: 9373 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:57:18 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-07-04 16:48:50 +0530 (Fri, 04 Jul 2014)");
  script_cve_id("CVE-2013-6370", "CVE-2013-6371");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for json-c RHSA-2014:0703-01");

  tag_insight = "JSON-C implements a reference counting object model that allows you to
easily construct JSON objects in C, output them as JSON-formatted strings,
and parse JSON-formatted strings back into the C representation of
JSON objects.

Multiple buffer overflow flaws were found in the way the json-c library
handled long strings in JSON documents. An attacker able to make an
application using json-c parse excessively large JSON input could cause the
application to crash. (CVE-2013-6370)

A denial of service flaw was found in the implementation of hash arrays in
json-c. An attacker could use this flaw to make an application using json-c
consume an excessive amount of CPU time by providing a specially crafted
JSON document that triggers multiple hash function collisions. To mitigate
this issue, json-c now uses a different hash function and randomization to
reduce the chance of an attacker successfully causing intentional
collisions. (CVE-2013-6371)

These issues were discovered by Florian Weimer of the Red Hat Product
Security Team.

All json-c users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.
";

  tag_affected = "json-c on Red Hat Enterprise Linux Server (v. 7)";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "RHSA", value: "2014:0703-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2014-June/msg00027.html");
  script_tag(name:"summary", value:"Check for the Version of json-c");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"json-c", rpm:"json-c~0.11~4.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"json-c-debuginfo", rpm:"json-c-debuginfo~0.11~4.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}