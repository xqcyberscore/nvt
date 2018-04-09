###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for resteasy-base RHSA-2014:1011-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871217");
  script_version("$Revision: 9373 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:57:18 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-08-06 12:05:23 +0200 (Wed, 06 Aug 2014)");
  script_cve_id("CVE-2014-3490", "CVE-2012-0818");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for resteasy-base RHSA-2014:1011-01");

  tag_insight = "RESTEasy contains a JBoss project that provides frameworks to help build
RESTful Web Services and RESTful Java applications. It is a fully certified
and portable implementation of the JAX-RS specification.

It was found that the fix for CVE-2012-0818 was incomplete: external
parameter entities were not disabled when the
resteasy.document.expand.entity.references parameter was set to false.
A remote attacker able to send XML requests to a RESTEasy endpoint could
use this flaw to read files accessible to the user running the application
server, and potentially perform other more advanced XXE attacks.
(CVE-2014-3490)

This issue was discovered by David Jorm of Red Hat Product Security.

All resteasy-base users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue.
";

  tag_affected = "resteasy-base on Red Hat Enterprise Linux Server (v. 7)";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "RHSA", value: "2014:1011-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2014-August/msg00005.html");
  script_tag(name:"summary", value:"Check for the Version of resteasy-base");
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

  if ((res = isrpmvuln(pkg:"resteasy-base-atom-provider", rpm:"resteasy-base-atom-provider~2.3.5~3.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-jaxb-provider", rpm:"resteasy-base-jaxb-provider~2.3.5~3.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-jaxrs", rpm:"resteasy-base-jaxrs~2.3.5~3.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-jaxrs-api", rpm:"resteasy-base-jaxrs-api~2.3.5~3.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-jettison-provider", rpm:"resteasy-base-jettison-provider~2.3.5~3.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}