###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for samba4 CESA-2013:1805 centos6 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881833");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-12-17 11:56:30 +0530 (Tue, 17 Dec 2013)");
  script_cve_id("CVE-2013-4408");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for samba4 CESA-2013:1805 centos6 ");

  tag_insight = "Samba is an open-source implementation of the Server Message Block (SMB) or
Common Internet File System (CIFS) protocol, which allows PC-compatible
machines to share files, printers, and other information.

A heap-based buffer overflow flaw was found in the DCE-RPC client code in
Samba. A specially crafted DCE-RPC packet could cause various Samba
programs to crash or, possibly, execute arbitrary code when parsed.
A malicious or compromised Active Directory Domain Controller could use
this flaw to compromise the winbindd daemon running with root privileges.
(CVE-2013-4408)

Red Hat would like to thank the Samba project for reporting this issue.
Upstream acknowledges Stefan Metzmacher and Michael Adam of SerNet as the
original reporters of this issue.

All users of Samba are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing this
update, the smb service will be restarted automatically.
";

  tag_affected = "samba4 on CentOS 6";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2013:1805");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-December/020055.html");
  script_tag(name: "summary" , value: "Check for the Version of samba4");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"samba4", rpm:"samba4~4.0.0~60.el6_5.rc4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-client", rpm:"samba4-client~4.0.0~60.el6_5.rc4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-common", rpm:"samba4-common~4.0.0~60.el6_5.rc4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-dc", rpm:"samba4-dc~4.0.0~60.el6_5.rc4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-dc-libs", rpm:"samba4-dc-libs~4.0.0~60.el6_5.rc4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-devel", rpm:"samba4-devel~4.0.0~60.el6_5.rc4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-libs", rpm:"samba4-libs~4.0.0~60.el6_5.rc4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-pidl", rpm:"samba4-pidl~4.0.0~60.el6_5.rc4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-python", rpm:"samba4-python~4.0.0~60.el6_5.rc4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-swat", rpm:"samba4-swat~4.0.0~60.el6_5.rc4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-test", rpm:"samba4-test~4.0.0~60.el6_5.rc4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-winbind", rpm:"samba4-winbind~4.0.0~60.el6_5.rc4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-winbind-clients", rpm:"samba4-winbind-clients~4.0.0~60.el6_5.rc4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-winbind-krb5-locator", rpm:"samba4-winbind-krb5-locator~4.0.0~60.el6_5.rc4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}