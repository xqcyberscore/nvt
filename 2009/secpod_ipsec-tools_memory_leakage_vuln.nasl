###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ipsec-tools_memory_leakage_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# IPSec-Tools Memory Leakage Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will let the attacker cause multiple memory leaks or
  memory consumption through signature verification during user authentication
  with X.509 certificates.

  Impact level: System/Application";

tag_affected = "IPsec Tools version prior to 0.7.2";
tag_insight = "Multiple memory leaks are cause due to error in eay_check_x509sign function in
  'src/racoon/crypto_openssl.c' and NAT Traversal keepalive implementation in
  'src/racoon/nattraversal.c' files.";
tag_solution = "Upgrade to the latest version 0.7.2
  http://ipsec-tools.sourceforge.net";
tag_summary = "This host is installed with IPSec-Tools for Linux and is prone
  to Memory Leakage Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900708");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1632");
  script_name("IPSec-Tools Memory Leakage Vulnerability");
  script_xref(name : "URL" , value : "https://trac.ipsec-tools.net/ticket/303");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/05/12/3");
  script_xref(name : "URL" , value : "http://sourceforge.net/project/shownotes.php?group_id=74601&release_id=677611");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_ipsec-tools_detect.nasl");
  script_require_keys("IPSec/Tools/Ver");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  exit(0);
}


include("version_func.inc");

ipsecVer = get_kb_item("IPSec/Tools/Ver");
if(ipsecVer == NULL){
  exit(0);
}

# Grep for IPSec-Tools version prior to 0.7.2
if(version_is_less(version:ipsecVer, test_version:"0.7.2")){
  security_message(0);
}
