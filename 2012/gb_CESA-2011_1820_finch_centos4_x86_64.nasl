###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for finch CESA-2011:1820 centos4 x86_64
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously.

  An input sanitization flaw was found in the way the AOL Open System for
  Communication in Realtime (OSCAR) protocol plug-in in Pidgin, used by the
  AOL ICQ and AIM instant messaging systems, escaped certain UTF-8
  characters. A remote attacker could use this flaw to crash Pidgin via a
  specially-crafted OSCAR message. (CVE-2011-4601)
  
  An input sanitization flaw was found in the way the Pidgin SILC (Secure
  Internet Live Conferencing) protocol plug-in escaped certain UTF-8
  characters in channel messages. A remote attacker could use this flaw to
  crash Pidgin via a specially-crafted SILC message. (CVE-2011-4603)
  
  Multiple NULL pointer dereference flaws were found in the Jingle extension
  of the Extensible Messaging and Presence Protocol (XMPP) protocol plug-in
  in Pidgin. A remote attacker could use these flaws to crash Pidgin via a
  specially-crafted Jingle multimedia message. (CVE-2011-4602)
  
  Red Hat would like to thank the Pidgin project for reporting these issues.
  Upstream acknowledges Evgeny Boger as the original reporter of
  CVE-2011-4601; Diego Bauche Madero from IOActive as the original reporter
  of CVE-2011-4603; and Thijs Alkemade as the original reporter of
  CVE-2011-4602.
  
  All Pidgin users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. Pidgin must be restarted for
  this update to take effect.";

tag_affected = "finch on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-December/018328.html");
  script_id(881340);
  script_version("$Revision: 8295 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 07:29:18 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:27:17 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-4601", "CVE-2011-4602", "CVE-2011-4603");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "CESA", value: "2011:1820");
  script_name("CentOS Update for finch CESA-2011:1820 centos4 x86_64");

  script_tag(name: "summary" , value: "Check for the Version of finch");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.6.6~10.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"finch-devel", rpm:"finch-devel~2.6.6~10.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.6.6~10.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.6.6~10.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-perl", rpm:"libpurple-perl~2.6.6~10.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-tcl", rpm:"libpurple-tcl~2.6.6~10.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.6.6~10.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-devel", rpm:"pidgin-devel~2.6.6~10.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.6.6~10.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
