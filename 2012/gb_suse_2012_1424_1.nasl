###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_1424_1.nasl 8285 2018-01-04 06:29:16Z teissa $
#
# SuSE Update for java-1_6_0-openjdk openSUSE-SU-2012:1424-1 (java-1_6_0-openjdk)
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
tag_affected = "java-1_6_0-openjdk on openSUSE 11.4";
tag_insight = "java 1.6.0 openjdk / icedtea was updated to 1.11.5
  (bnc#785433)
  * Security fixes
  - S6631398, CVE-2012-3216: FilePermission improved path
  checking
  - S7093490: adjust package access in rmiregistry
  - S7143535, CVE-2012-5068: ScriptEngine corrected
  permissions
  - S7167656, CVE-2012-5077: Multiple Seeders are being
  created
  - S7169884, CVE-2012-5073: LogManager checks do not work
  correctly for sub-types
  - S7169888, CVE-2012-5075: Narrowing resource definitions
  in JMX RMI connector
  - S7172522, CVE-2012-5072: Improve DomainCombiner checking
  - S7186286, CVE-2012-5081: TLS implementation to better
  adhere to RFC
  - S7189103, CVE-2012-5069: Executors needs to maintain
  state
  - S7189490: More improvements to DomainCombiner checking
  - S7189567, CVE-2012-5085: java net obselete protocol
  - S7192975, CVE-2012-5071: Conditional usage check is
  wrong
  - S7195194, CVE-2012-5084: Better data validation for
  Swing
  - S7195917, CVE-2012-5086: XMLDecoder parsing at
  close-time should be improved
  - S7195919, CVE-2012-5079: (sl) ServiceLoader can throw
  CCE without needing to create instance
  - S7198296, CVE-2012-5089: Refactor classloader usage
  - S7158800: Improve storage of symbol tables
  - S7158801: Improve VM CompileOnly option
  - S7158804: Improve config file parsing
  - S7176337: Additional changes needed for 7158801 fix
  - S7198606, CVE-2012-4416: Improve VM optimization
  * Backports
  - S7175845: &quot;jar uf&quot; changes file permissions unexpectedly
  - S7177216: native2ascii changes file permissions of
  input file
  - S7199153: TEST_BUG: try-with-resources syntax pushed to
  6-open repo
  * Bug fixes
  - PR1194: IcedTea tries to build with
  /usr/lib/jvm/java-openjdk (now a 1.7 VM) by default";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_id(850360);
  script_version("$Revision: 8285 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 07:29:16 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-12-13 17:01:26 +0530 (Thu, 13 Dec 2012)");
  script_cve_id("CVE-2012-3216", "CVE-2012-4416", "CVE-2012-5068", "CVE-2012-5069",
                "CVE-2012-5071", "CVE-2012-5072", "CVE-2012-5073", "CVE-2012-5075",
                "CVE-2012-5077", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5084",
                "CVE-2012-5085", "CVE-2012-5086", "CVE-2012-5089");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "openSUSE-SU", value: "2012:1424_1");
  script_name("SuSE Update for java-1_6_0-openjdk openSUSE-SU-2012:1424-1 (java-1_6_0-openjdk)");

  script_tag(name: "summary" , value: "Check for the Version of java-1_6_0-openjdk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
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

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"java-1_6_0-openjdk", rpm:"java-1_6_0-openjdk~1.6.0.0_b24.1.11.5~21.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-openjdk-debuginfo", rpm:"java-1_6_0-openjdk-debuginfo~1.6.0.0_b24.1.11.5~21.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-openjdk-debugsource", rpm:"java-1_6_0-openjdk-debugsource~1.6.0.0_b24.1.11.5~21.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-openjdk-demo", rpm:"java-1_6_0-openjdk-demo~1.6.0.0_b24.1.11.5~21.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-openjdk-demo-debuginfo", rpm:"java-1_6_0-openjdk-demo-debuginfo~1.6.0.0_b24.1.11.5~21.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-openjdk-devel", rpm:"java-1_6_0-openjdk-devel~1.6.0.0_b24.1.11.5~21.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-openjdk-devel-debuginfo", rpm:"java-1_6_0-openjdk-devel-debuginfo~1.6.0.0_b24.1.11.5~21.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-openjdk-javadoc", rpm:"java-1_6_0-openjdk-javadoc~1.6.0.0_b24.1.11.5~21.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-openjdk-src", rpm:"java-1_6_0-openjdk-src~1.6.0.0_b24.1.11.5~21.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
