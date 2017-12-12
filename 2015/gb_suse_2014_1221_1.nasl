###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1221_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for wireshark SUSE-SU-2014:1221-1 (wireshark)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850802");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2014-6421", "CVE-2014-6422", "CVE-2014-6423", "CVE-2014-6424", "CVE-2014-6427", "CVE-2014-6428", "CVE-2014-6429", "CVE-2014-6430", "CVE-2014-6431", "CVE-2014-6432", "CVE-2014-5161", "CVE-2014-5162", "CVE-2014-5163", "CVE-2014-5164", "CVE-2014-5165");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for wireshark SUSE-SU-2014:1221-1 (wireshark)");
  script_tag(name: "summary", value: "Check the version of wireshark");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  The wireshark package was upgraded to 1.10.10 from 1.8.x as 1.8 was
  discontinued.

  This update fixes vulnerabilities that could allow an attacker to crash
  Wireshark or make it become unresponsive by sending specific packets onto
  the network or have them loaded via a capture file while the dissectors
  are running. It also contains a number of other bug fixes.

  * RTP dissector crash. (wnpa-sec-2014-12 CVE-2014-6421 CVE-2014-6422)
  * MEGACO dissector infinite loop. (wnpa-sec-2014-13 CVE-2014-6423)
  * Netflow dissector crash. (wnpa-sec-2014-14 CVE-2014-6424)
  * RTSP dissector crash. (wnpa-sec-2014-17 CVE-2014-6427)
  * SES dissector crash. (wnpa-sec-2014-18 CVE-2014-6428)
  * Sniffer file parser crash. (wnpa-sec-2014-19 CVE-2014-6429
  CVE-2014-6430 CVE-2014-6431 CVE-2014-6432)
  * The Catapult DCT2000 and IrDA dissectors could underrun a buffer.
  (wnpa-sec-2014-08 CVE-2014-5161 CVE-2014-5162, bnc#889901)
  * The GSM Management dissector could crash. (wnpa-sec-2014-09
  CVE-2014-5163, bnc#889906)
  * The RLC dissector could crash. (wnpa-sec-2014-10 CVE-2014-5164,
  bnc#889900)
  * The ASN.1 BER dissector could crash. (wnpa-sec-2014-11
  CVE-2014-5165, bnc#889899)

  Further bug fixes as listed in:
https://www.wireshark.org/docs/relnotes/wireshark-1.10.10.html
https://www.wireshark.org/docs/relnotes/wireshark-1.10.10.html  and
https://www.wireshark.org/docs/relnotes/wireshark-1.10.9.html
https://www.wireshark.org/docs/relnotes/wireshark-1.10.9.html  .

  Security Issues:

  * CVE-2014-5161
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-5161 
  * CVE-2014-5162
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-5162 
  * CVE-2014-5163
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-5163 
  * CVE-2014-5164
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-5164 
  * CVE-2014-5165
   <a  rel='nofollow' href='http://cve.mitre.org/c ... 

  Description truncated, for more information please check the Reference URL");
  script_tag(name: "affected", value: "wireshark on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2014:1221_1");
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

if(release == "SLES11.0SP3")
{

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.10.10~0.2.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
