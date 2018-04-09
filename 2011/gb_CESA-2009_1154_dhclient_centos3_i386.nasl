###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for dhclient CESA-2009:1154 centos3 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The Dynamic Host Configuration Protocol (DHCP) is a protocol that allows
  individual devices on an IP network to get their own network configuration
  information, including an IP address, a subnet mask, and a broadcast
  address.

  The Mandriva Linux Engineering Team discovered a stack-based buffer
  overflow flaw in the ISC DHCP client. If the DHCP client were to receive a
  malicious DHCP response, it could crash or execute arbitrary code with the
  permissions of the client (root). (CVE-2009-0692)
  
  An insecure temporary file use flaw was discovered in the DHCP daemon's
  init script (&quot;/etc/init.d/dhcpd&quot;). A local attacker could use this flaw to
  overwrite an arbitrary file with the output of the &quot;dhcpd -t&quot; command via
  a symbolic link attack, if a system administrator executed the DHCP init
  script with the &quot;configtest&quot;, &quot;restart&quot;, or &quot;reload&quot; option.
  (CVE-2009-1893)
  
  Users of DHCP should upgrade to these updated packages, which contain
  backported patches to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "dhclient on CentOS 3";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2009-July/016034.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880710");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "CESA", value: "2009:1154");
  script_cve_id("CVE-2009-0692", "CVE-2009-1893");
  script_name("CentOS Update for dhclient CESA-2009:1154 centos3 i386");

  script_tag(name:"summary", value:"Check for the Version of dhclient");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"dhclient", rpm:"dhclient~3.0.1~10.2_EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dhcp", rpm:"dhcp~3.0.1~10.2_EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~3.0.1~10.2_EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
