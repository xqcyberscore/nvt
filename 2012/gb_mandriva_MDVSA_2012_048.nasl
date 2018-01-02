###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for mutt MDVSA-2012:048 (mutt)
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
tag_insight = "A vulnerability has been found and corrected in mutt:

  Mutt does not verify that the smtps server hostname matches the
  domain name of the subject of an X.509 certificate, which allows
  man-in-the-middle attackers to spoof an SSL SMTP server via an
  arbitrary certificate, a different vulnerability than CVE-2009-3766
  (CVE-2011-1429).

  The updated packages have been patched to correct this issue.";

tag_affected = "mutt on Mandriva Linux 2011.0,
  Mandriva Linux 2010.1";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:048");
  script_id(831651);
  script_version("$Revision: 8257 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-29 07:29:46 +0100 (Fri, 29 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-08-03 09:58:39 +0530 (Fri, 03 Aug 2012)");
  script_cve_id("CVE-2009-3766", "CVE-2011-1429");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDVSA", value: "2012:048");
  script_name("Mandriva Update for mutt MDVSA-2012:048 (mutt)");

  script_tag(name: "summary" , value: "Check for the Version of mutt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"mutt", rpm:"mutt~1.5.21~4.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mutt-doc", rpm:"mutt-doc~1.5.21~4.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mutt-utf8", rpm:"mutt-utf8~1.5.21~4.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"mutt", rpm:"mutt~1.5.20~8.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mutt-doc", rpm:"mutt-doc~1.5.20~8.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mutt-utf8", rpm:"mutt-utf8~1.5.20~8.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
