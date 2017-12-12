###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0824_3.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for MozillaFirefox SUSE-SU-2014:0824-3 (MozillaFirefox)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850984");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-16 16:11:07 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2014-1533", "CVE-2014-1534", "CVE-2014-1536", "CVE-2014-1537", "CVE-2014-1538", "CVE-2014-1541", "CVE-2014-1545");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MozillaFirefox SUSE-SU-2014:0824-3 (MozillaFirefox)");
  script_tag(name: "summary", value: "Check the version of MozillaFirefox");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  MozillaFirefox was updated to version 24.6.0 to fix six security issues:

  * Miscellaneous memory safety hazards. (CVE-2014-1533, CVE-2014-1534)
  * Use-after-free and out of bounds issues found using Address
  Sanitizer. (CVE-2014-1536, CVE-2014-1537, CVE-2014-1538)
  * Use-after-free with SMIL Animation Controller. (CVE-2014-1541)

  mozilla-nspr was updated to version 4.10.6 to fix one security issue:

  * Out of bounds write in NSPR. (CVE-2014-1545)

  Further information can be found at
  https://www.mozilla.org/security/announce/
   
  Security Issues references:

  * CVE-2014-1533
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1533 
  * CVE-2014-1534
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1534 
  * CVE-2014-1536
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1536 
  * CVE-2014-1537
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1537 
  * CVE-2014-1538
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1538 
  * CVE-2014-1541
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1541 
  * CVE-2014-1545
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1545");
  script_tag(name: "affected", value: "MozillaFirefox on SUSE Linux Enterprise Server 11 SP2 LTSS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2014:0824_3");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "SLES11.0SP2")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~24.6.0esr~0.3.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED-24", rpm:"MozillaFirefox-branding-SLED-24~0.4.10.24", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~24.6.0esr~0.3.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.16.1~0.3.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.10.6~0.3.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.10.6~0.3.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.16.1~0.3.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.16.1~0.3.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.16.1~0.3.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.16.1~0.3.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.10.6~0.3.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.16.1~0.3.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
