###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for libtirpc RHSA-2013:0884-01
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
tag_insight = "These packages provide a transport-independent RPC (remote procedure call)
  implementation.

  A flaw was found in the way libtirpc decoded RPC requests. A
  specially-crafted RPC request could cause libtirpc to attempt to free a
  buffer provided by an application using the library, even when the buffer
  was not dynamically allocated. This could cause an application using
  libtirpc, such as rpcbind, to crash. (CVE-2013-1950)

  Red Hat would like to thank Michael Armstrong for reporting this issue.

  Users of libtirpc should upgrade to these updated packages, which contain a
  backported patch to correct this issue. All running applications using
  libtirpc must be restarted for the update to take effect.";


tag_solution = "Please Install the Updated Packages.";
tag_affected = "libtirpc on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";


if(description)
{
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_id(871002);
  script_version("$Revision: 8483 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 07:58:04 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-05-31 09:50:33 +0530 (Fri, 31 May 2013)");
  script_cve_id("CVE-2013-1950");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("RedHat Update for libtirpc RHSA-2013:0884-01");

  script_xref(name: "RHSA", value: "2013:0884-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2013-May/msg00039.html");
  script_tag(name: "summary" , value: "Check for the Version of libtirpc");
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

  if ((res = isrpmvuln(pkg:"libtirpc", rpm:"libtirpc~0.2.1~6.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtirpc-debuginfo", rpm:"libtirpc-debuginfo~0.2.1~6.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
