###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_2563-01_openssh.nasl 7080 2017-09-08 05:49:48Z asteins $
#
# RedHat Update for openssh RHSA-2017:2563-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811729");
  script_version("$Revision: 7080 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-08 07:49:48 +0200 (Fri, 08 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-09-01 06:52:40 +0200 (Fri, 01 Sep 2017)");
  script_cve_id("CVE-2016-6210");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for openssh RHSA-2017:2563-01");
  script_tag(name: "summary", value: "Check the version of openssh");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "OpenSSH is an SSH protocol implementation
supported by a number of Linux, UNIX, and similar operating systems. It includes
the core files necessary for both the OpenSSH client and server.

Security Fix(es):

* A covert timing channel flaw was found in the way OpenSSH handled
authentication of non-existent users. A remote unauthenticated attacker
could possibly use this flaw to determine valid user names by measuring the
timing of server responses. (CVE-2016-6210)
");
  script_tag(name: "affected", value: "openssh on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2017:2563-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2017-August/msg00086.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~5.3p1~123.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~5.3p1~123.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~5.3p1~123.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-debuginfo", rpm:"openssh-debuginfo~5.3p1~123.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~5.3p1~123.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
