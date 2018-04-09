###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for gnutls CESA-2014:0246 centos6 
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
  script_oid("1.3.6.1.4.1.25623.1.0.881893");
  script_version("$Revision: 9373 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:57:18 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-03-12 09:27:50 +0530 (Wed, 12 Mar 2014)");
  script_cve_id("CVE-2014-0092");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("CentOS Update for gnutls CESA-2014:0246 centos6 ");

  tag_insight = "The GnuTLS library provides support for cryptographic algorithms and for
protocols such as Transport Layer Security (TLS).

It was discovered that GnuTLS did not correctly handle certain errors that
could occur during the verification of an X.509 certificate, causing it to
incorrectly report a successful verification. An attacker could use this
flaw to create a specially crafted certificate that could be accepted by
GnuTLS as valid for a site chosen by the attacker. (CVE-2014-0092)

The CVE-2014-0092 issue was discovered by Nikos Mavrogiannopoulos of the
Red Hat Security Technologies Team.

Users of GnuTLS are advised to upgrade to these updated packages, which
correct this issue. For the update to take effect, all applications linked
to the GnuTLS library must be restarted.
";

  tag_affected = "gnutls on CentOS 6";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2014:0246");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2014-March/020185.html");
  script_tag(name:"summary", value:"Check for the Version of gnutls");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~2.8.5~13.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-devel", rpm:"gnutls-devel~2.8.5~13.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-guile", rpm:"gnutls-guile~2.8.5~13.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-utils", rpm:"gnutls-utils~2.8.5~13.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
