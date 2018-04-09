###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for wireshark MDVSA-2011:105 (wireshark)
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
tag_insight = "This advisory updates wireshark to the latest version (1.2.17),
  fixing several security issues:

  * Large/infinite loop in the DICOM dissector. (Bug 5876) Versions
  affected: 1.2.0 to 1.2.16 and 1.4.0 to 1.4.6.
  
  * Huzaifa Sidhpurwala of the Red Hat Security Response Team
  discovered that a corrupted Diameter dictionary file could crash
  Wireshark. Versions affected: 1.2.0 to 1.2.16 and 1.4.0 to 1.4.6.
  
  * Huzaifa Sidhpurwala of the Red Hat Security Response Team discovered
  that a corrupted snoop file could crash Wireshark. (Bug 5912) Versions
  affected: 1.2.0 to 1.2.16 and 1.4.0 to 1.4.6.
  
  * David Maciejak of Fortinet&amp;#039;s FortiGuard Labs discovered that
  malformed compressed capture data could crash Wireshark. (Bug 5908)
  Versions affected: 1.2.0 to 1.2.16 and 1.4.0 to 1.4.6.
  
  * Huzaifa Sidhpurwala of the Red Hat Security Response Team discovered
  that a corrupted Visual Networks file could crash Wireshark. (Bug 5934)
  Versions affected: 1.2.0 to 1.2.16 and 1.4.0 to 1.4.6.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "wireshark on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2011-06/msg00001.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831413");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-06 16:56:27 +0200 (Mon, 06 Jun 2011)");
   script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2011:105");
  script_name("Mandriva Update for wireshark MDVSA-2011:105 (wireshark)");

  script_tag(name:"summary", value:"Check for the Version of wireshark");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~1.2.17~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark0", rpm:"libwireshark0~1.2.17~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~1.2.17~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~1.2.17~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tshark", rpm:"tshark~1.2.17~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.2.17~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~1.2.17~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark0", rpm:"lib64wireshark0~1.2.17~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~1.2.17~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~1.2.17~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark0", rpm:"libwireshark0~1.2.17~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~1.2.17~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~1.2.17~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tshark", rpm:"tshark~1.2.17~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.2.17~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~1.2.17~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark0", rpm:"lib64wireshark0~1.2.17~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~1.2.17~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
