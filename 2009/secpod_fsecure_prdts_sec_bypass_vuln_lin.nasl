###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_fsecure_prdts_sec_bypass_vuln_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# F-Secure Products Security Bypass Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful attacks can allow attackers to bypass scanning detection and
  possibly launch further attacks on the vulnerable system.
  Impact Level: Application";
tag_affected = "F-Secure Linux Security prior to 7.03 build 81803
  F-Secure Internet Gatekeeper for Linux prior to 3.02 build 1221
  F-Secure Anti-Virus Linux Client and Server Security 5.54 and prior";
tag_insight = "Error in the file parsing engine can be exploited to bypass the anti-virus
  scanning functionality via a specially crafted ZIP or RAR file.";
tag_solution = "Apply patch or Upgrade to Higher version
  http://www.f-secure.com/en_EMEA/downloads
  http://www.f-secure.com/en_EMEA/support/security-advisory/fsc-2009-1.html";
tag_summary = "This host is installed with F-Secure Product and is prone to
  Security Bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900363");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-17 17:54:48 +0200 (Wed, 17 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1782");
  script_bugtraq_id(34849);
  script_name("F-Secure Products Security Bypass Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35008");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50346");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1262");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Malware");
  script_dependencies("gb_fsecure_prdts_detect_lin.nasl");
  script_mandatory_keys("F-Sec/Products/Lin/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

# Linux Security
fsavVer = get_kb_item("F-Sec/AV/LnxSec/Ver");
if(fsavVer != NULL)
{
  # Grep for version < 7.03 build 81803
  if(version_is_less(version:fsavVer, test_version:"7.03.81803"))
  {
    security_message(0);
    exit(0);
  }
}

# Linux Client Security
fslcsVer = get_kb_item("F-Sec/AV/LnxClntSec/Ver");
if(fslcsVer != NULL)
{
  # Grep for version <= 5.54
  if(version_is_less_equal(version:fslcsVer, test_version:"5.54"))
  {
    security_message(0);
    exit(0);
  }
}

# Linux Server Security
fslssVer = get_kb_item("F-Sec/AV/LnxSerSec/Ver");
if(fslssVer != NULL)
{
  # Grep for version <= 5.54
  if(version_is_less_equal(version:fslssVer, test_version:"5.54"))
  {
    security_message(0);
    exit(0);
  }
}

# Internet Gatekeeper
fsigkVer = get_kb_item("F-Sec/IntGatekeeper/Lnx/Ver");
if(fsigkVer != NULL)
{
  # Grep for version < 3.02 build 1221
  if(version_is_less(version:fsigkVer, test_version:"3.02.1221")){
    security_message(0);
  }
}
