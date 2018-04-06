###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libgcrypt CESA-2013:1457 centos5 
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
  script_oid("1.3.6.1.4.1.25623.1.0.881812");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-10-29 15:36:25 +0530 (Tue, 29 Oct 2013)");
  script_cve_id("CVE-2013-4242");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_name("CentOS Update for libgcrypt CESA-2013:1457 centos5 ");

  tag_insight = "The libgcrypt library provides general-purpose implementations of various
cryptographic algorithms.

It was found that GnuPG was vulnerable to the Yarom/Falkner flush+reload
cache side-channel attack on the RSA secret exponent. An attacker able to
execute a process on the logical CPU that shared the L3 cache with the
GnuPG process (such as a different local user or a user of a KVM guest
running on the same host with the kernel same-page merging functionality
enabled) could possibly use this flaw to obtain portions of the RSA secret
key. (CVE-2013-4242)

All libgcrypt users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue.
";

  tag_affected = "libgcrypt on CentOS 5";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2013:1457");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-October/019992.html");
  script_tag(name: "summary" , value: "Check for the Version of libgcrypt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"libgcrypt", rpm:"libgcrypt~1.4.4~7.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcrypt-devel", rpm:"libgcrypt-devel~1.4.4~7.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}