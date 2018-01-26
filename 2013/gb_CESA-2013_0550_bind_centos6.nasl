###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for bind CESA-2013:0550 centos6
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
tag_insight = "The Berkeley Internet Name Domain (BIND) is an implementation of the
  Domain Name System (DNS) protocols. BIND includes a DNS server (named); a
  resolver library (routines for applications to use when interfacing with
  DNS); and tools for verifying that the DNS server is operating correctly.
  DNS64 is used to automatically generate DNS records so IPv6 based clients
  can access IPv4 systems through a NAT64 server.

  A flaw was found in the DNS64 implementation in BIND when using Response
  Policy Zones (RPZ). If a remote attacker sent a specially-crafted query to
  a named server that is using RPZ rewrite rules, named could exit
  unexpectedly with an assertion failure. Note that DNS64 support is not
  enabled by default. (CVE-2012-5689)

  This update also adds the following enhancement:

  * Previously, it was impossible to configure the the maximum number of
  responses sent per second to one client. This allowed remote attackers to
  conduct traffic amplification attacks using DNS queries with spoofed source
  IP addresses. With this update, it is possible to use the new &quot;rate-limit&quot;
  configuration option in named.conf and configure the maximum number of
  queries which the server responds to. Refer to the BIND documentation for
  more details about the &quot;rate-limit&quot; option. (BZ#906312)

  All bind users are advised to upgrade to these updated packages, which
  contain patches to correct this issue and add this enhancement. After
  installing the update, the BIND daemon (named) will be restarted
  automatically.";


tag_affected = "bind on CentOS 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2013-March/019615.html");
  script_id(881663);
  script_version("$Revision: 8526 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 07:57:37 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-03-12 10:01:23 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2012-5689");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_xref(name: "CESA", value: "2013:0550");
  script_name("CentOS Update for bind CESA-2013:0550 centos6 ");

  script_tag(name: "summary" , value: "Check for the Version of bind");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.8.2~0.17.rc1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.8.2~0.17.rc1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.8.2~0.17.rc1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.8.2~0.17.rc1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-sdb", rpm:"bind-sdb~9.8.2~0.17.rc1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.8.2~0.17.rc1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
